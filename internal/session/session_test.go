package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

// setup returns a Manager backed by a fresh in-memory database, plus the ID
// of a user that sessions can belong to (the schema requires a real user).
func setup(t *testing.T, secure bool) (*Manager, *store.Store, string) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	u := &store.User{UserName: "test@example.com", Active: true}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return New(st, time.Hour, secure), st, u.ID
}

// startSession signs the user in and returns the cookie the browser would store.
func startSession(t *testing.T, m *Manager, r *http.Request, userID string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := m.Start(context.Background(), rec, r, userID, "oidc"); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	return cookies[0]
}

// requestWith builds an incoming request carrying cookie c.
func requestWith(c *http.Cookie) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	return req
}

// The cookie carries every browser-side protection we rely on.
func TestStartSetsHardenedCookie(t *testing.T) {
	m, _, userID := setup(t, true)
	c := startSession(t, m, nil, userID)

	if c.Name != "__Host-sid" {
		t.Errorf("cookie name = %q, want __Host-sid", c.Name)
	}
	if !c.HttpOnly {
		t.Error("cookie must be HttpOnly so JavaScript (and XSS) can't read it")
	}
	if !c.Secure {
		t.Error("cookie must be Secure on HTTPS")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Path != "/" || c.Domain != "" {
		t.Errorf("Path=%q Domain=%q; the __Host- prefix requires Path=/ and no Domain", c.Path, c.Domain)
	}
	if len(c.Value) < 43 { // 32 random bytes, base64url-encoded
		t.Errorf("token too short: %d chars", len(c.Value))
	}
}

// Over plain HTTP (local dev) the __Host- prefix can't be used.
func TestPlainHTTPUsesUnprefixedCookie(t *testing.T) {
	m, _, userID := setup(t, false)
	c := startSession(t, m, nil, userID)
	if c.Name != "sid" || c.Secure {
		t.Errorf("got name=%q secure=%v, want sid / not secure", c.Name, c.Secure)
	}
}

// Only the token's SHA-256 hash is stored, so a copy of the database
// can't be turned back into working cookies.
func TestDatabaseStoresOnlyTokenHash(t *testing.T) {
	m, st, userID := setup(t, true)
	c := startSession(t, m, nil, userID)
	ctx := context.Background()

	if _, err := st.GetSession(ctx, c.Value); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("raw token is a database key; only its hash should be (err=%v)", err)
	}
	if _, err := st.GetSession(ctx, hashToken(c.Value)); err != nil {
		t.Errorf("session not found by hash: %v", err)
	}
}

// Signing out deletes the session server-side, so a copied cookie stops working.
func TestEndRevokesSession(t *testing.T) {
	m, _, userID := setup(t, true)
	c := startSession(t, m, nil, userID)
	req := requestWith(c)

	if _, err := m.Current(req); err != nil {
		t.Fatalf("session should be valid before End: %v", err)
	}

	rec := httptest.NewRecorder()
	if err := m.End(rec, req); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Current(req); !errors.Is(err, ErrNoSession) {
		t.Fatalf("old cookie still works after End: err=%v", err)
	}
	// The browser is also told to delete its cookie.
	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Errorf("End should send an expired cookie, got %+v", cleared)
	}
}

// Session fixation: signing in must issue a NEW token and kill any session
// the browser already carried, so a token planted before login is useless.
func TestStartRotatesExistingSession(t *testing.T) {
	m, _, userID := setup(t, true)
	before := startSession(t, m, nil, userID)

	after := startSession(t, m, requestWith(before), userID)

	if after.Value == before.Value {
		t.Fatal("Start reused the existing token")
	}
	if _, err := m.Current(requestWith(before)); !errors.Is(err, ErrNoSession) {
		t.Errorf("pre-login token still valid after new login: err=%v", err)
	}
	if _, err := m.Current(requestWith(after)); err != nil {
		t.Errorf("new token should be valid: %v", err)
	}
}

// Expiry is enforced server-side, not just by the browser's cookie expiry.
func TestSessionExpires(t *testing.T) {
	m, st, userID := setup(t, true)
	now := time.Now()
	m.now = func() time.Time { return now }
	st.SetClock(func() time.Time { return now })

	c := startSession(t, m, nil, userID)
	req := requestWith(c)
	if _, err := m.Current(req); err != nil {
		t.Fatalf("fresh session: %v", err)
	}

	st.SetClock(func() time.Time { return now.Add(time.Hour + time.Second) })
	if _, err := m.Current(req); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session should be expired after its TTL: err=%v", err)
	}
}

// Requests with no cookie, or a forged one, are anonymous.
func TestMissingOrForgedCookie(t *testing.T) {
	m, _, _ := setup(t, true)

	if _, err := m.Current(httptest.NewRequest("GET", "/", nil)); !errors.Is(err, ErrNoSession) {
		t.Errorf("no cookie: want ErrNoSession, got %v", err)
	}
	forged := &http.Cookie{Name: "__Host-sid", Value: "made-up-token"}
	if _, err := m.Current(requestWith(forged)); !errors.Is(err, ErrNoSession) {
		t.Errorf("forged cookie: want ErrNoSession, got %v", err)
	}
}
