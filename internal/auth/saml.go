package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

// SAMLConfig configures the SAML service provider (this app).
type SAMLConfig struct {
	EntityID string // SP issuer, also the audience Okta puts in assertions
	ACSURL   string // Assertion Consumer Service: where Okta POSTs the response
	SLOURL   string // Single Logout endpoint

	Key         *rsa.PrivateKey   // signs our LogoutRequests
	Certificate *x509.Certificate // published in our metadata, uploaded to Okta

	IDPMetadata *saml.EntityDescriptor // Okta's signing cert and endpoints

	Store *store.Store // assertion replay cache
}

// SAML is a SAML 2.0 service provider using SP-initiated SSO.
type SAML struct {
	sp *saml.ServiceProvider
}

// LoadSAMLKeyPair reads the SP key and certificate written by cmd/gencert.
func LoadSAMLKeyPair(keyFile, certFile string) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read SAML SP key (run `go run ./cmd/gencert`): %w", err)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read SAML SP certificate (run `go run ./cmd/gencert`): %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	cb, _ := pem.Decode(certPEM)
	if kb == nil || cb == nil {
		return nil, nil, errors.New("SAML SP key or certificate is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse SAML SP key: %w", err)
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("SAML SP key must be RSA")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse SAML SP certificate: %w", err)
	}
	if time.Now().After(cert.NotAfter) {
		return nil, nil, fmt.Errorf("SAML SP certificate expired on %s", cert.NotAfter.Format(time.DateOnly))
	}
	return key, cert, nil
}

// FetchIDPMetadata downloads and parses Okta's SAML metadata, which carries
// the IdP's entity ID, SSO/SLO endpoints and the certificate it signs with.
func FetchIDPMetadata(ctx context.Context, metadataURL string) (*saml.EntityDescriptor, error) {
	u, err := url.Parse(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("SAML_IDP_METADATA_URL: %w", err)
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		// The metadata carries the certificate we trust for signatures, so it
		// must not be fetchable over plain HTTP from a real host.
		return nil, errors.New("SAML_IDP_METADATA_URL must use https")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch SAML IdP metadata: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch SAML IdP metadata: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseIDPMetadata(body)
}

// ParseIDPMetadata parses a single-entity IdP metadata document.
func ParseIDPMetadata(data []byte) (*saml.EntityDescriptor, error) {
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(data, &md); err != nil {
		return nil, fmt.Errorf("parse SAML IdP metadata: %w", err)
	}
	if md.EntityID == "" || len(md.IDPSSODescriptors) == 0 {
		return nil, errors.New("SAML IdP metadata has no IDPSSODescriptor")
	}
	return &md, nil
}

// NewSAML builds the service provider.
func NewSAML(cfg SAMLConfig) (*SAML, error) {
	parse := func(name, s string) (url.URL, error) {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return url.URL{}, fmt.Errorf("invalid SAML %s URL %q", name, s)
		}
		return *u, nil
	}
	entity, err := parse("entity ID", cfg.EntityID)
	if err != nil {
		return nil, err
	}
	acs, err := parse("ACS", cfg.ACSURL)
	if err != nil {
		return nil, err
	}
	slo, err := parse("SLO", cfg.SLOURL)
	if err != nil {
		return nil, err
	}
	if cfg.Key == nil || cfg.Certificate == nil || cfg.IDPMetadata == nil || cfg.Store == nil {
		return nil, errors.New("SAML config is missing key, certificate, IdP metadata or store")
	}

	sp := &saml.ServiceProvider{
		EntityID:    cfg.EntityID,
		Key:         cfg.Key,
		Certificate: cfg.Certificate,
		MetadataURL: entity,
		AcsURL:      acs,
		SloURL:      slo,
		IDPMetadata: cfg.IDPMetadata,
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},

		// Okta's "Name ID format: EmailAddress" setting must match.
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
		// Only responses to a request we sent are accepted (no IdP-initiated
		// SSO), which ties every assertion to an InResponseTo we issued.
		AllowIDPInitiated: false,
		// Okta signs with RSA-SHA256; refuse anything weaker.
		RejectSHA1Signatures: true,
		// Sign LogoutRequests: Okta rejects unsigned ones. AuthnRequests are
		// left unsigned (Okta doesn't require it unless configured to).
		LogoutSignatureMethod: dsig.RSASHA256SignatureMethod,
		LogoutBindings:        []string{saml.HTTPRedirectBinding},
		LimitRelayStateLength: true,
		ReplayCache:           replayCache{cfg.Store},
	}
	if sp.GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" {
		return nil, errors.New("IdP metadata has no HTTP-Redirect SSO endpoint")
	}
	return &SAML{sp: sp}, nil
}

// Metadata returns this SP's metadata XML (entity ID, ACS, SLO, signing cert).
func (s *SAML) Metadata() ([]byte, error) {
	b, err := xml.MarshalIndent(s.sp.Metadata(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}

// SAMLRequest is an outgoing AuthnRequest or LogoutRequest.
type SAMLRequest struct {
	ID         string // must come back as InResponseTo
	RelayState string // random; maps the response back to ID server-side
	URL        string // where to send the browser (HTTP-Redirect binding)
}

// NewAuthnRequest builds an SP-initiated login request.
func (s *SAML) NewAuthnRequest() (SAMLRequest, error) {
	req, err := s.sp.MakeAuthenticationRequest(
		s.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return SAMLRequest{}, err
	}
	relay, err := randomString()
	if err != nil {
		return SAMLRequest{}, err
	}
	u, err := req.Redirect(relay, s.sp)
	if err != nil {
		return SAMLRequest{}, err
	}
	return SAMLRequest{ID: req.ID, RelayState: relay, URL: u.String()}, nil
}

// SAMLIdentity is what a verified assertion says about the user.
type SAMLIdentity struct {
	NameID       string // Okta username (EmailAddress format)
	SessionIndex string // Okta's session, needed for Single Logout
	OktaID       string // optional "oktaId" attribute: Okta's stable user ID
	Email        string
	FirstName    string
	LastName     string
	Groups       []string
	HasGroups    bool // a "groups" attribute was present
}

// ParseResponse verifies a SAML response POSTed to the ACS. The library
// checks: XML signature against Okta's certificate (on the response or the
// assertion), issuer, Destination and Recipient (our ACS), Audience (our
// entity ID), NotBefore/NotOnOrAfter with clock skew, InResponseTo equal to
// requestID, and that the assertion ID hasn't been used before.
func (s *SAML) ParseResponse(r *http.Request, requestID string) (SAMLIdentity, error) {
	if err := r.ParseForm(); err != nil {
		return SAMLIdentity{}, err
	}
	// Artifact binding would make us call back to the IdP; we don't use it.
	if r.Form.Get("SAMLart") != "" {
		return SAMLIdentity{}, errors.New("SAML artifact binding is not accepted")
	}
	a, err := s.sp.ParseResponse(r, []string{requestID})
	if err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			// PrivateErr has the real reason; it goes to the audit log only.
			return SAMLIdentity{}, fmt.Errorf("invalid SAML response: %w", ire.PrivateErr)
		}
		return SAMLIdentity{}, fmt.Errorf("invalid SAML response: %w", err)
	}

	var id SAMLIdentity
	if a.Subject != nil && a.Subject.NameID != nil {
		id.NameID = strings.TrimSpace(a.Subject.NameID.Value)
	}
	for _, st := range a.AuthnStatements {
		if st.SessionIndex != "" {
			id.SessionIndex = st.SessionIndex
			break
		}
	}
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			name := attr.Name
			if name == "" {
				name = attr.FriendlyName
			}
			var vals []string
			for _, v := range attr.Values {
				if v.Value != "" {
					vals = append(vals, v.Value)
				}
			}
			first := ""
			if len(vals) > 0 {
				first = vals[0]
			}
			switch strings.ToLower(name) {
			case "email":
				id.Email = first
			case "firstname":
				id.FirstName = first
			case "lastname":
				id.LastName = first
			case "oktaid":
				id.OktaID = first
			case "groups":
				id.Groups, id.HasGroups = vals, true
			}
		}
	}
	if id.NameID == "" {
		return SAMLIdentity{}, errors.New("assertion has no NameID")
	}
	return id, nil
}

// NewLogoutRequest builds a signed SP-initiated LogoutRequest. It returns a
// zero SAMLRequest (empty URL) if the IdP metadata has no SLO endpoint.
func (s *SAML) NewLogoutRequest(nameID, sessionIndex string) (SAMLRequest, error) {
	dest := s.sp.GetSLOBindingLocation(saml.HTTPRedirectBinding)
	if dest == "" || nameID == "" {
		return SAMLRequest{}, nil
	}
	var opts []saml.LogoutRequestOption
	if sessionIndex != "" {
		opts = append(opts, saml.WithSessionIndex(sessionIndex))
	}
	req, err := s.sp.MakeLogoutRequest(dest, nameID, opts...)
	if err != nil {
		return SAMLRequest{}, err
	}
	relay, err := randomString()
	if err != nil {
		return SAMLRequest{}, err
	}
	u, err := s.sp.RedirectLogoutRequestURL(req, relay)
	if err != nil {
		return SAMLRequest{}, err
	}
	return SAMLRequest{ID: req.ID, RelayState: relay, URL: u.String()}, nil
}

// ParseLogoutResponse verifies Okta's LogoutResponse (signature, issuer,
// destination, InResponseTo == requestID, success status).
func (s *SAML) ParseLogoutResponse(r *http.Request, requestID string) error {
	_, err := s.sp.ParseLogoutResponse(r, []string{requestID})
	return err
}

// replayCache stores accepted assertion IDs in the database.
type replayCache struct{ st *store.Store }

func (c replayCache) Consume(assertionID string, expiresAt time.Time) error {
	err := c.st.ConsumeAssertionID(context.Background(), assertionID, expiresAt)
	if errors.Is(err, store.ErrAlreadyUsed) {
		return saml.ErrAssertionReplayed
	}
	return err
}
