package web

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"html"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/auth"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

// The tests drive a real SAML IdP from the same library (crewjam/saml),
// configured to send Okta-style attributes, standing in for Okta.

const idpBase = "https://idp.example.com"

func newKeyCert(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

// testIdP is the stand-in for Okta.
type testIdP struct {
	t    *testing.T
	idp  *saml.IdentityProvider
	user *saml.Session // who is "signed in" at the IdP
	sp   *saml.EntityDescriptor

	// audience, if set, makes the IdP issue assertions for another SP
	// (it signs them correctly; only the audience is wrong).
	audience string
}

func (ti *testIdP) GetSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	return ti.user
}

func (ti *testIdP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if ti.sp == nil || id != ti.sp.EntityID {
		return nil, saml.ErrUnknownServiceProvider
	}
	if ti.audience != "" {
		other := *ti.sp
		other.EntityID = ti.audience
		return &other, nil
	}
	return ti.sp, nil
}

// oktaAssertions makes assertions shaped like Okta's: NameID is the
// username, attributes are email/firstName/lastName/groups (+ oktaId).
type oktaAssertions struct{}

func (oktaAssertions) MakeAssertion(req *saml.IdpAuthnRequest, s *saml.Session) error {
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, s); err != nil {
		return err
	}
	attr := func(name string, vals ...string) saml.Attribute {
		a := saml.Attribute{Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"}
		for _, v := range vals {
			a.Values = append(a.Values, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		return a
	}
	attrs := []saml.Attribute{
		attr("email", s.UserEmail), attr("firstName", s.UserGivenName),
		attr("lastName", s.UserSurname), attr("oktaId", s.UserName),
	}
	if s.Groups != nil {
		attrs = append(attrs, attr("groups", s.Groups...))
	}
	req.Assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: attrs}}
	return nil
}

func mustURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *u
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, cert := newKeyCert(t, "test idp")
	ti := &testIdP{t: t}
	ti.idp = &saml.IdentityProvider{
		Key: key, Signer: key, Certificate: cert,
		Logger:                  log.New(io.Discard, "", 0),
		MetadataURL:             mustURL(idpBase + "/metadata"),
		SSOURL:                  mustURL(idpBase + "/sso"),
		LogoutURL:               mustURL(idpBase + "/slo"),
		ServiceProviderProvider: ti,
		SessionProvider:         ti,
		AssertionMaker:          oktaAssertions{},
		SignatureMethod:         dsig.RSASHA256SignatureMethod,
	}
	return ti
}

// oktaUserSession is a signed-in Okta user.
func oktaUserSession(login string, groups ...string) *saml.Session {
	now := time.Now()
	return &saml.Session{
		ID: "s-" + login, CreateTime: now, ExpireTime: now.Add(time.Hour), Index: "idx-" + login,
		NameID: login, NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserName: "00u" + strings.Split(login, "@")[0], UserEmail: login,
		UserGivenName: "Ann", UserSurname: "Example", Groups: groups,
	}
}

type samlHarness struct {
	*harness
	idp    *testIdP
	spKey  *rsa.PrivateKey
	spCert *x509.Certificate
}

const spBase = "http://localhost:8080"

func newSAMLHarness(t *testing.T, env map[string]string) *samlHarness {
	t.Helper()
	ti := newTestIdP(t)
	spKey, spCert := newKeyCert(t, "test sp")
	var sp *auth.SAML
	hs := newHarnessFn(t, env, func(st *store.Store) Options {
		var err error
		sp, err = auth.NewSAML(auth.SAMLConfig{
			EntityID: spBase + "/saml/metadata", ACSURL: spBase + "/saml/acs", SLOURL: spBase + "/saml/slo",
			Key: spKey, Certificate: spCert, IDPMetadata: ti.idp.Metadata(), Store: st,
		})
		if err != nil {
			t.Fatal(err)
		}
		return Options{SAML: sp}
	})
	// The IdP learns about the SP from the SP's own metadata, as Okta would.
	md, err := sp.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	ti.sp = &saml.EntityDescriptor{}
	if err := xml.Unmarshal(md, ti.sp); err != nil {
		t.Fatal(err)
	}
	// Okta doesn't encrypt assertions unless told to, so neither does the
	// test IdP: drop the SP's encryption key from what the IdP sees. That
	// also keeps the XML readable for the tampering tests.
	for i := range ti.sp.SPSSODescriptors {
		var kds []saml.KeyDescriptor
		for _, kd := range ti.sp.SPSSODescriptors[i].KeyDescriptors {
			if kd.Use != "encryption" {
				kds = append(kds, kd)
			}
		}
		ti.sp.SPSSODescriptors[i].KeyDescriptors = kds
	}
	return &samlHarness{harness: hs, idp: ti, spKey: spKey, spCert: spCert}
}

var formField = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)

// parseIdPForm extracts the auto-submitting form the IdP returns.
func parseIdPForm(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("IdP returned %d: %s", rec.Code, rec.Body.String())
	}
	form := url.Values{}
	for _, m := range formField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	if form.Get("SAMLResponse") == "" {
		t.Fatal("IdP response has no SAMLResponse")
	}
	return form
}

// startSAML hits /saml/login and lets the IdP answer the AuthnRequest.
func (sh *samlHarness) startSAML(user *saml.Session) url.Values {
	sh.t.Helper()
	res := sh.do("GET", "/saml/login", nil)
	if res.StatusCode != http.StatusFound {
		sh.t.Fatalf("/saml/login = %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, idpBase+"/sso?") {
		sh.t.Fatalf("redirected to %s, want the IdP SSO URL", loc)
	}
	sh.idp.user = user
	rec := httptest.NewRecorder()
	sh.idp.idp.ServeSSO(rec, httptest.NewRequest("GET", loc, nil))
	return parseIdPForm(sh.t, rec)
}

func (sh *samlHarness) postACS(form url.Values) *http.Response {
	req := httptest.NewRequest("POST", spBase+"/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return sh.serve(req)
}

func (sh *samlHarness) samlLogin(user *saml.Session) *http.Response {
	sh.t.Helper()
	return sh.postACS(sh.startSAML(user))
}

func TestSAMLLoginMapsAttributesAndRole(t *testing.T) {
	sh := newSAMLHarness(t, nil)
	res := sh.samlLogin(oktaUserSession("ann@example.com", "app-admin", "Everyone"))
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/dashboard" {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("ACS = %d %s: %s", res.StatusCode, res.Header.Get("Location"), body)
	}
	sid := cookieNamed(res, "sid")
	if sid == nil {
		t.Fatal("no session cookie after SAML login")
	}
	if r := sh.do("GET", "/admin", sid); r.StatusCode != http.StatusOK {
		t.Fatalf("admin = %d, want 200", r.StatusCode)
	}

	u, err := sh.st.GetUserByUserName(context.Background(), "ann@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "ann@example.com" || u.GivenName != "Ann" || u.FamilyName != "Example" ||
		u.ExternalID != "00uann" || u.DisplayName != "Ann Example" {
		t.Fatalf("attributes not mapped: %+v", u)
	}
	if e := lastAudit(t, sh.st, "login.success"); !strings.Contains(e.Detail, `"saml"`) {
		t.Fatalf("login.success detail = %s", e.Detail)
	}
}

func TestSAMLViewerCannotReachAdmin(t *testing.T) {
	sh := newSAMLHarness(t, nil)
	sid := cookieNamed(sh.samlLogin(oktaUserSession("bea@example.com", "app-viewer")), "sid")
	if r := sh.do("GET", "/dashboard", sid); r.StatusCode != http.StatusOK {
		t.Fatalf("dashboard = %d", r.StatusCode)
	}
	if r := sh.do("GET", "/admin", sid); r.StatusCode != http.StatusForbidden {
		t.Fatalf("admin = %d, want 403", r.StatusCode)
	}
}

// tamper decodes a SAMLResponse, edits the XML, and re-encodes it.
func tamper(t *testing.T, form url.Values, from, to string) url.Values {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(from)) {
		t.Fatalf("%q not in response", from)
	}
	out := url.Values{}
	for k, v := range form {
		out[k] = v
	}
	out.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes.ReplaceAll(raw, []byte(from), []byte(to))))
	return out
}

func TestSAMLRejectsBadResponses(t *testing.T) {
	tests := []struct {
		name string
		run  func(sh *samlHarness) *http.Response
	}{
		{"replayed response", func(sh *samlHarness) *http.Response {
			// A different user, so the shared "x@ was not created" check
			// still means something for this case.
			form := sh.startSAML(oktaUserSession("r@example.com", "app-admin"))
			if r := sh.postACS(form); r.StatusCode != http.StatusSeeOther {
				sh.t.Fatalf("first post = %d", r.StatusCode)
			}
			return sh.postACS(form)
		}},
		{"RelayState that we never issued", func(sh *samlHarness) *http.Response {
			form := sh.startSAML(oktaUserSession("x@example.com", "app-admin"))
			form.Set("RelayState", "forged")
			return sh.postACS(form)
		}},
		{"unsolicited IdP-initiated response", func(sh *samlHarness) *http.Response {
			sh.idp.user = oktaUserSession("x@example.com", "app-admin")
			rec := httptest.NewRecorder()
			sh.idp.idp.ServeIDPInitiated(rec, httptest.NewRequest("GET", idpBase+"/start", nil),
				spBase+"/saml/metadata", "anything")
			return sh.postACS(parseIdPForm(sh.t, rec))
		}},
		{"NameID changed after signing", func(sh *samlHarness) *http.Response {
			form := sh.startSAML(oktaUserSession("x@example.com", "app-viewer"))
			return sh.postACS(tamper(sh.t, form, "x@example.com", "y@example.com"))
		}},
		{"groups changed after signing", func(sh *samlHarness) *http.Response {
			form := sh.startSAML(oktaUserSession("x@example.com", "app-viewer"))
			return sh.postACS(tamper(sh.t, form, ">app-viewer<", ">app-admin<"))
		}},
		{"signed by a different IdP key", func(sh *samlHarness) *http.Response {
			res := sh.do("GET", "/saml/login", nil)
			impostor := newTestIdP(sh.t) // same URLs and entity ID, different key
			impostor.sp, impostor.user = sh.idp.sp, oktaUserSession("x@example.com", "app-admin")
			rec := httptest.NewRecorder()
			impostor.idp.ServeSSO(rec, httptest.NewRequest("GET", res.Header.Get("Location"), nil))
			return sh.postACS(parseIdPForm(sh.t, rec))
		}},
		{"assertion for a different SP (audience)", func(sh *samlHarness) *http.Response {
			sh.idp.audience = "https://other-app.example.com"
			return sh.postACS(sh.startSAML(oktaUserSession("x@example.com", "app-admin")))
		}},
		{"expired assertion", func(sh *samlHarness) *http.Response {
			form := sh.startSAML(oktaUserSession("x@example.com", "app-admin"))
			saml.TimeNow = func() time.Time { return time.Now().UTC().Add(time.Hour) }
			defer func() { saml.TimeNow = func() time.Time { return time.Now().UTC() } }()
			return sh.postACS(form)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sh := newSAMLHarness(t, nil)
			res := tt.run(sh)
			if res.StatusCode != http.StatusBadRequest {
				body, _ := io.ReadAll(res.Body)
				t.Fatalf("status = %d, want 400: %s", res.StatusCode, body)
			}
			if cookieNamed(res, "sid") != nil {
				t.Fatal("a session cookie was issued for a rejected response")
			}
			t.Logf("rejected because: %s", lastAudit(t, sh.st, "login.failure").Detail)
			if _, err := sh.st.GetUserByUserName(context.Background(), "x@example.com"); err == nil {
				t.Fatal("a rejected response still created a user")
			}
		})
	}
}

func TestSAMLMissingGroupsAttributeKeepsRoles(t *testing.T) {
	sh := newSAMLHarness(t, nil)
	sh.samlLogin(oktaUserSession("cal@example.com", "app-viewer"))

	noGroups := oktaUserSession("cal@example.com")
	noGroups.Groups = nil // Okta omits the attribute when no group matches the filter
	sid := cookieNamed(sh.samlLogin(noGroups), "sid")
	if r := sh.do("GET", "/dashboard", sid); r.StatusCode != http.StatusOK {
		t.Fatalf("dashboard = %d; a missing groups attribute must not strip roles", r.StatusCode)
	}
}

func TestSAMLWithoutJITRequiresProvisionedUser(t *testing.T) {
	sh := newSAMLHarness(t, map[string]string{"JIT_PROVISIONING": "false"})
	res := sh.samlLogin(oktaUserSession("dee@example.com", "app-admin"))
	if res.StatusCode != http.StatusForbidden || cookieNamed(res, "sid") != nil {
		t.Fatalf("unprovisioned user = %d, want 403", res.StatusCode)
	}
}

func inflate(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestSAMLLogoutSendsSignedLogoutRequest(t *testing.T) {
	sh := newSAMLHarness(t, nil)
	sid := cookieNamed(sh.samlLogin(oktaUserSession("eve@example.com", "app-viewer")), "sid")

	res := sh.do("POST", "/logout", sid)
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, idpBase+"/slo?") {
		t.Fatalf("logout = %d %s, want redirect to IdP SLO", res.StatusCode, loc)
	}
	if r := sh.do("GET", "/dashboard", sid); r.StatusCode != http.StatusSeeOther {
		t.Fatal("local session still valid after logout")
	}

	u, _ := url.Parse(loc)
	q := u.Query()
	xmlReq := inflate(t, q.Get("SAMLRequest"))
	for _, want := range []string{"LogoutRequest", ">eve@example.com<", "idx-eve@example.com"} {
		if !strings.Contains(xmlReq, want) {
			t.Fatalf("LogoutRequest missing %q:\n%s", want, xmlReq)
		}
	}

	// HTTP-Redirect binding signature: over the raw, still-encoded
	// "SAMLRequest=..&RelayState=..&SigAlg=.." string, with our SP key.
	if q.Get("SigAlg") != dsig.RSASHA256SignatureMethod {
		t.Fatalf("SigAlg = %q", q.Get("SigAlg"))
	}
	raw := map[string]string{}
	for _, part := range strings.Split(u.RawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		raw[k] = v
	}
	signed := "SAMLRequest=" + raw["SAMLRequest"] + "&RelayState=" + raw["RelayState"] + "&SigAlg=" + raw["SigAlg"]
	sig, err := base64.StdEncoding.DecodeString(q.Get("Signature"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(sh.spCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("LogoutRequest signature doesn't verify with the SP certificate: %v", err)
	}
}

func TestSAMLUnsolicitedLogoutResponseIsAudited(t *testing.T) {
	sh := newSAMLHarness(t, nil)
	res := sh.do("GET", "/saml/slo?SAMLResponse=bm90LXNhbWw%3D&RelayState=never-issued", nil)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("slo = %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if e := lastAudit(t, sh.st, "logout.idp_response"); e.Outcome != "failure" {
		t.Fatalf("outcome = %s", e.Outcome)
	}
}

func TestSAMLMetadataDescribesSP(t *testing.T) {
	sh := newSAMLHarness(t, nil)
	res := sh.do("GET", "/saml/metadata", nil)
	body, _ := io.ReadAll(res.Body)
	for _, want := range []string{
		`entityID="` + spBase + `/saml/metadata"`,
		`Location="` + spBase + `/saml/acs"`,
		`Location="` + spBase + `/saml/slo"`,
		base64.StdEncoding.EncodeToString(sh.spCert.Raw)[:40],
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("metadata missing %q", want)
		}
	}
}
