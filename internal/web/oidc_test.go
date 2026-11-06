package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/auth"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

// fakeIdP is a minimal OpenID provider standing in for Okta: discovery,
// JWKS, and a token endpoint that enforces PKCE and client authentication.
// The /authorize step is simulated by authorize(), since there's no browser.
type fakeIdP struct {
	t        *testing.T
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	secret   string

	mu     sync.Mutex
	grants map[string]grant // authorization code -> grant
}

// grant is what the IdP remembers between /authorize and /token, plus knobs
// that let a test make the IdP misbehave.
type grant struct {
	nonce, challenge, redirectURI string
	claims                        map[string]any
	signWith                      *rsa.PrivateKey // nil = the real key
	nonceOverride                 string
	ttl                           time.Duration
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, key: key, clientID: "test-client", secret: "test-secret", grants: map[string]grant{}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"end_session_endpoint":                  f.srv.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("POST /token", f.handleToken)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// authorize plays the part of Okta's /authorize endpoint after the user has
// signed in: it checks the request and returns a code for the callback.
func (f *fakeIdP) authorize(authURL string, g grant) (code, state string) {
	f.t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != f.clientID {
		f.t.Fatalf("bad authorize request: %s", u.RawQuery)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		f.t.Fatal("authorize request is missing a PKCE S256 challenge")
	}
	if !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		f.t.Fatalf("scope missing openid: %q", q.Get("scope"))
	}
	if q.Get("nonce") == "" || q.Get("state") == "" {
		f.t.Fatal("authorize request is missing nonce or state")
	}
	g.nonce, g.challenge, g.redirectURI = q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")

	code = fmt.Sprintf("code-%d", time.Now().UnixNano())
	f.mu.Lock()
	f.grants[code] = g
	f.mu.Unlock()
	return code, q.Get("state")
}

func (f *fakeIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != f.clientID || secret != f.secret {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"error": "invalid_client"})
		return
	}

	f.mu.Lock()
	g, found := f.grants[r.PostForm.Get("code")]
	delete(f.grants, r.PostForm.Get("code")) // codes are single use
	f.mu.Unlock()

	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case r.PostForm.Get("grant_type") != "authorization_code", !found:
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	case base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge:
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	case r.PostForm.Get("redirect_uri") != g.redirectURI:
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
		return
	}

	writeJSON(w, map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
		"id_token": f.idToken(g),
	})
}

func (f *fakeIdP) idToken(g grant) string {
	f.t.Helper()
	now := time.Now()
	ttl := g.ttl
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	nonce := g.nonce
	if g.nonceOverride != "" {
		nonce = g.nonceOverride
	}
	claims := map[string]any{
		"iss": f.srv.URL, "aud": f.clientID, "iat": now.Unix(), "exp": now.Add(ttl).Unix(),
		"nonce": nonce,
	}
	for k, v := range g.claims {
		claims[k] = v
	}
	key := f.key
	if g.signWith != nil {
		key = g.signWith
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		f.t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// oktaUser returns typical Okta ID token claims.
func oktaUser(login string, groups ...string) map[string]any {
	return map[string]any{
		"sub": "00u" + strings.Split(login, "@")[0], "preferred_username": login, "email": login,
		"email_verified": true, "name": "Test User", "given_name": "Test", "family_name": "User",
		"groups": groups,
	}
}

// newOIDCHarness wires a server to a fake IdP. extraEnv overrides defaults.
func newOIDCHarness(t *testing.T, extraEnv map[string]string) (*harness, *fakeIdP) {
	t.Helper()
	f := newFakeIdP(t)
	env := map[string]string{
		"OIDC_ISSUER": f.srv.URL, "OIDC_CLIENT_ID": f.clientID, "OIDC_CLIENT_SECRET": f.secret,
	}
	for k, v := range extraEnv {
		env[k] = v
	}
	o, err := auth.NewOIDC(auth.OIDCConfig{
		Issuer: f.srv.URL, ClientID: f.clientID, ClientSecret: f.secret,
		RedirectURL: "http://localhost:8080/oidc/callback", Scopes: []string{"openid", "profile", "email", "groups"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return newHarnessWith(t, env, Options{OIDC: o}), f
}

func (hs *harness) serve(req *http.Request) *http.Response {
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec.Result()
}

func cookieNamed(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

// startLogin hits /oidc/login and returns the Okta URL and the state cookie.
func (hs *harness) startLogin() (string, *http.Cookie) {
	hs.t.Helper()
	res := hs.do("GET", "/oidc/login", nil)
	if res.StatusCode != http.StatusFound {
		hs.t.Fatalf("/oidc/login = %d, want 302", res.StatusCode)
	}
	sc := cookieNamed(res, oidcStateCookie)
	if sc == nil || !sc.HttpOnly {
		hs.t.Fatal("missing or non-HttpOnly state cookie")
	}
	return res.Header.Get("Location"), sc
}

func (hs *harness) callback(code, state string, sc *http.Cookie) *http.Response {
	req := httptest.NewRequest("GET", "/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	if sc != nil {
		req.AddCookie(sc)
	}
	return hs.serve(req)
}

// login runs the whole flow and returns the callback response.
func (hs *harness) login(f *fakeIdP, g grant) *http.Response {
	hs.t.Helper()
	authURL, sc := hs.startLogin()
	code, state := f.authorize(authURL, g)
	return hs.callback(code, state, sc)
}

func lastAudit(t *testing.T, st *store.Store, typ string) store.AuditEvent {
	t.Helper()
	events, _ := st.ListAudit(context.Background(), 50)
	for _, e := range events {
		if e.Type == typ {
			return e
		}
	}
	t.Fatalf("no %s audit event", typ)
	return store.AuditEvent{}
}

func TestOIDCLoginJITProvisionsAndGrantsRole(t *testing.T) {
	hs, f := newOIDCHarness(t, nil)

	res := hs.login(f, grant{claims: oktaUser("ada@example.com", "app-admin", "Everyone")})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/dashboard" {
		t.Fatalf("callback = %d %s, want 303 /dashboard", res.StatusCode, res.Header.Get("Location"))
	}
	sid := cookieNamed(res, "sid")
	if sid == nil {
		t.Fatal("no session cookie after login")
	}
	if r := hs.do("GET", "/admin", sid); r.StatusCode != http.StatusOK {
		t.Fatalf("admin page = %d, want 200", r.StatusCode)
	}

	u, err := hs.st.GetUserByUserName(context.Background(), "ada@example.com")
	if err != nil || u.ExternalID != "00uada" || u.GivenName != "Test" {
		t.Fatalf("JIT user not created correctly: %+v %v", u, err)
	}
	lastAudit(t, hs.st, "login.jit_provision")
	if e := lastAudit(t, hs.st, "login.success"); !strings.Contains(e.Detail, `"oidc"`) {
		t.Fatalf("login.success detail = %s", e.Detail)
	}
}

func TestOIDCLoginRefreshesGroupsEachSignIn(t *testing.T) {
	hs, f := newOIDCHarness(t, nil)
	hs.login(f, grant{claims: oktaUser("bo@example.com", "app-admin")})

	// Removed from app-admin in Okta; signs in again.
	res := hs.login(f, grant{claims: oktaUser("bo@example.com", "app-viewer")})
	sid := cookieNamed(res, "sid")
	if r := hs.do("GET", "/admin", sid); r.StatusCode != http.StatusForbidden {
		t.Fatalf("admin after demotion = %d, want 403", r.StatusCode)
	}
}

func TestOIDCMissingGroupsClaimKeepsExistingGroups(t *testing.T) {
	hs, f := newOIDCHarness(t, nil)
	hs.login(f, grant{claims: oktaUser("cy@example.com", "app-viewer")})

	claims := oktaUser("cy@example.com")
	delete(claims, "groups") // e.g. groups claim filter misconfigured in Okta
	res := hs.login(f, grant{claims: claims})
	if r := hs.do("GET", "/dashboard", cookieNamed(res, "sid")); r.StatusCode != http.StatusOK {
		t.Fatalf("dashboard = %d; a missing groups claim must not strip roles", r.StatusCode)
	}
}

func TestOIDCRejectsBadCallbacks(t *testing.T) {
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name string
		run  func(hs *harness, f *fakeIdP) *http.Response
	}{
		{"state does not match cookie", func(hs *harness, f *fakeIdP) *http.Response {
			authURL, sc := hs.startLogin()
			code, _ := f.authorize(authURL, grant{claims: oktaUser("x@example.com", "app-admin")})
			return hs.callback(code, "attacker-state", sc)
		}},
		{"no state cookie (login CSRF)", func(hs *harness, f *fakeIdP) *http.Response {
			authURL, _ := hs.startLogin()
			code, state := f.authorize(authURL, grant{claims: oktaUser("x@example.com", "app-admin")})
			return hs.callback(code, state, nil)
		}},
		{"token signed by an unknown key", func(hs *harness, f *fakeIdP) *http.Response {
			return hs.login(f, grant{claims: oktaUser("x@example.com", "app-admin"), signWith: otherKey})
		}},
		{"expired token", func(hs *harness, f *fakeIdP) *http.Response {
			return hs.login(f, grant{claims: oktaUser("x@example.com", "app-admin"), ttl: -time.Minute})
		}},
		{"nonce from a different login", func(hs *harness, f *fakeIdP) *http.Response {
			return hs.login(f, grant{claims: oktaUser("x@example.com", "app-admin"), nonceOverride: "replayed"})
		}},
		{"token for another app (audience)", func(hs *harness, f *fakeIdP) *http.Response {
			c := oktaUser("x@example.com", "app-admin")
			c["aud"] = "some-other-client"
			return hs.login(f, grant{claims: c})
		}},
		{"token from another issuer", func(hs *harness, f *fakeIdP) *http.Response {
			c := oktaUser("x@example.com", "app-admin")
			c["iss"] = "https://evil.example.com"
			return hs.login(f, grant{claims: c})
		}},
		{"made-up authorization code", func(hs *harness, f *fakeIdP) *http.Response {
			_, sc := hs.startLogin()
			return hs.callback("forged-code", sc.Value, sc)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs, f := newOIDCHarness(t, nil)
			res := tt.run(hs, f)
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", res.StatusCode)
			}
			if cookieNamed(res, "sid") != nil {
				t.Fatal("a session cookie was issued for a rejected login")
			}
			lastAudit(t, hs.st, "login.failure")
			if _, err := hs.st.GetUserByUserName(context.Background(), "x@example.com"); err == nil {
				t.Fatal("a rejected login still created a user")
			}
		})
	}
}

func TestOIDCCallbackCannotBeReplayed(t *testing.T) {
	hs, f := newOIDCHarness(t, nil)
	authURL, sc := hs.startLogin()
	code, state := f.authorize(authURL, grant{claims: oktaUser("di@example.com", "app-viewer")})

	if res := hs.callback(code, state, sc); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("first callback = %d", res.StatusCode)
	}
	if res := hs.callback(code, state, sc); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback = %d, want 400", res.StatusCode)
	}
}

func TestOIDCIdPErrorIsShownAndAudited(t *testing.T) {
	hs, _ := newOIDCHarness(t, nil)
	res := hs.do("GET", "/oidc/callback?error=access_denied&error_description=User+is+not+assigned+to+the+client+application.", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
	if e := lastAudit(t, hs.st, "login.failure"); !strings.Contains(e.Detail, "access_denied") {
		t.Fatalf("audit detail = %s", e.Detail)
	}
}

func TestOIDCWithoutJITRequiresProvisionedUser(t *testing.T) {
	hs, f := newOIDCHarness(t, map[string]string{"JIT_PROVISIONING": "false"})

	res := hs.login(f, grant{claims: oktaUser("ed@example.com", "app-admin")})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("unprovisioned user = %d, want 403", res.StatusCode)
	}

	// Once SCIM (simulated here) has created the user, login works, and the
	// token's groups claim is ignored: SCIM-managed groups decide the role.
	ctx := context.Background()
	u := &store.User{UserName: "ed@example.com", Active: true}
	_ = hs.st.CreateUser(ctx, u)
	_ = hs.st.AddGroupMember(ctx, hs.group["app-viewer"].ID, u.ID)

	res = hs.login(f, grant{claims: oktaUser("ed@example.com", "app-admin")})
	sid := cookieNamed(res, "sid")
	if sid == nil {
		t.Fatalf("provisioned user could not sign in: %d", res.StatusCode)
	}
	if r := hs.do("GET", "/admin", sid); r.StatusCode != http.StatusForbidden {
		t.Fatalf("token claimed app-admin but SCIM says viewer: admin = %d, want 403", r.StatusCode)
	}
}

func TestOIDCDeactivatedUserCannotSignIn(t *testing.T) {
	hs, f := newOIDCHarness(t, nil)
	hs.login(f, grant{claims: oktaUser("flo@example.com", "app-viewer")})
	u, _ := hs.st.GetUserByUserName(context.Background(), "flo@example.com")
	_ = hs.st.SetUserActive(context.Background(), u.ID, false)

	res := hs.login(f, grant{claims: oktaUser("flo@example.com", "app-viewer")})
	if res.StatusCode != http.StatusForbidden || cookieNamed(res, "sid") != nil {
		t.Fatalf("deactivated user got status %d", res.StatusCode)
	}
}

func TestOIDCLogoutEndsOktaSessionToo(t *testing.T) {
	hs, f := newOIDCHarness(t, nil)
	sid := cookieNamed(hs.login(f, grant{claims: oktaUser("gus@example.com", "app-viewer")}), "sid")

	res := hs.do("POST", "/logout", sid)
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusSeeOther || loc.Path != "/logout" ||
		!strings.HasPrefix(res.Header.Get("Location"), f.srv.URL) {
		t.Fatalf("logout redirect = %d %s, want Okta end-session", res.StatusCode, res.Header.Get("Location"))
	}
	if loc.Query().Get("id_token_hint") == "" ||
		loc.Query().Get("post_logout_redirect_uri") != "http://localhost:8080/" {
		t.Fatalf("logout URL missing id_token_hint or post_logout_redirect_uri: %s", loc.RawQuery)
	}
	if r := hs.do("GET", "/dashboard", sid); r.StatusCode != http.StatusSeeOther {
		t.Fatal("local session still valid after logout")
	}
}
