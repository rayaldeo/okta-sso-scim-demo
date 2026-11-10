package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/config"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/session"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

type harness struct {
	t     *testing.T
	srv   *Server
	st    *store.Store
	h     http.Handler
	group map[string]*store.Group
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil, Options{}) }

// newHarnessWith builds a server from the given environment variables.
func newHarnessWith(t *testing.T, env map[string]string, opts Options) *harness {
	return newHarnessFn(t, env, func(*store.Store) Options { return opts })
}

// newHarnessFn is newHarnessWith for options that need the store.
func newHarnessFn(t *testing.T, env map[string]string, mkOpts func(*store.Store) Options) *harness {
	t.Helper()
	cfg, err := config.FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	srv, err := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), mkOpts(st))
	if err != nil {
		t.Fatal(err)
	}
	hs := &harness{t: t, srv: srv, st: st, h: srv.Handler(), group: map[string]*store.Group{}}
	for _, name := range []string{"app-admin", "app-viewer"} {
		g := &store.Group{DisplayName: name}
		if err := st.CreateGroup(context.Background(), g); err != nil {
			t.Fatal(err)
		}
		hs.group[name] = g
	}
	return hs
}

// signIn creates a user in the given groups and returns a valid session cookie,
// standing in for a completed SAML/OIDC login.
func (hs *harness) signIn(userName string, groups ...string) (*store.User, *http.Cookie) {
	hs.t.Helper()
	ctx := context.Background()
	u := &store.User{UserName: userName, Email: userName, Active: true}
	if err := hs.st.CreateUser(ctx, u); err != nil {
		hs.t.Fatal(err)
	}
	for _, g := range groups {
		if err := hs.st.AddGroupMember(ctx, hs.group[g].ID, u.ID); err != nil {
			hs.t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	if err := hs.srv.Sessions().Start(ctx, rec, nil, session.Login{UserID: u.ID, Method: "oidc"}); err != nil {
		hs.t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		hs.t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	return u, cookies[0]
}

func (hs *harness) do(method, path string, c *http.Cookie) *http.Response {
	req := httptest.NewRequest(method, path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestHealthz(t *testing.T) {
	hs := newHarness(t)
	if res := hs.do("GET", "/healthz", nil); res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	hs := newHarness(t)
	res := hs.do("GET", "/", nil)
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if res.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
}

func TestRBAC(t *testing.T) {
	hs := newHarness(t)
	_, admin := hs.signIn("admin@example.com", "app-admin")
	_, viewer := hs.signIn("viewer@example.com", "app-viewer")
	_, nobody := hs.signIn("nobody@example.com")

	tests := []struct {
		name   string
		path   string
		cookie *http.Cookie
		want   int
	}{
		{"anonymous dashboard redirects", "/dashboard", nil, http.StatusSeeOther},
		{"anonymous admin redirects", "/admin", nil, http.StatusSeeOther},
		{"no-role user denied dashboard", "/dashboard", nobody, http.StatusForbidden},
		{"viewer sees dashboard", "/dashboard", viewer, http.StatusOK},
		{"viewer denied admin", "/admin", viewer, http.StatusForbidden},
		{"admin sees dashboard", "/dashboard", admin, http.StatusOK},
		{"admin sees admin", "/admin", admin, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if res := hs.do("GET", tt.path, tt.cookie); res.StatusCode != tt.want {
				t.Fatalf("GET %s = %d, want %d", tt.path, res.StatusCode, tt.want)
			}
		})
	}

	// Denials are audited.
	events, _ := hs.st.ListAudit(context.Background(), 10)
	var denied int
	for _, e := range events {
		if e.Type == "authz.denied" {
			denied++
		}
	}
	if denied != 2 {
		t.Fatalf("want 2 authz.denied events, got %d", denied)
	}
}

func TestGroupChangeTakesEffectImmediately(t *testing.T) {
	hs := newHarness(t)
	u, c := hs.signIn("eve@example.com", "app-admin")
	if res := hs.do("GET", "/admin", c); res.StatusCode != 200 {
		t.Fatalf("admin before change: %d", res.StatusCode)
	}
	// Simulates Okta removing eve from app-admin via SCIM, mid-session.
	if err := hs.st.RemoveGroupMember(context.Background(), hs.group["app-admin"].ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if res := hs.do("GET", "/admin", c); res.StatusCode != http.StatusForbidden {
		t.Fatalf("admin after removal: %d, want 403", res.StatusCode)
	}
}

func TestDeactivatedUserLosesAccess(t *testing.T) {
	hs := newHarness(t)
	u, c := hs.signIn("frank@example.com", "app-viewer")
	if err := hs.st.SetUserActive(context.Background(), u.ID, false); err != nil {
		t.Fatal(err)
	}
	if res := hs.do("GET", "/dashboard", c); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("deactivated user: %d, want redirect to login", res.StatusCode)
	}
}

func TestLogoutEndsSession(t *testing.T) {
	hs := newHarness(t)
	_, c := hs.signIn("gina@example.com", "app-viewer")

	if res := hs.do("GET", "/logout", c); res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /logout should be rejected, got %d", res.StatusCode)
	}
	if res := hs.do("POST", "/logout", c); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /logout: %d", res.StatusCode)
	}
	if res := hs.do("GET", "/dashboard", c); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("old cookie still works after logout: %d", res.StatusCode)
	}
}

func TestDashboardEscapesUserData(t *testing.T) {
	hs := newHarness(t)
	_, c := hs.signIn(`<script>alert(1)</script>@example.com`, "app-viewer")
	res := hs.do("GET", "/dashboard", c)
	body, _ := io.ReadAll(res.Body)
	if strings.Contains(string(body), "<script>alert(1)") {
		t.Fatal("user-controlled data was not HTML-escaped")
	}
}
