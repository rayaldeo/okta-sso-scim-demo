// Package web wires the HTTP routes, middleware and HTML pages.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/audit"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/config"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/rbac"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/session"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server holds the app's dependencies.
type Server struct {
	cfg      config.Config
	store    *store.Store
	sessions *session.Manager
	audit    *audit.Logger
	roles    rbac.Mapping
	log      *slog.Logger
	pages    map[string]*template.Template
}

// New builds a Server and parses its templates.
func New(cfg config.Config, st *store.Store, log *slog.Logger) (*Server, error) {
	s := &Server{
		cfg:      cfg,
		store:    st,
		sessions: session.New(st, cfg.SessionTTL, cfg.SecureCookies()),
		audit:    audit.New(st, log),
		roles:    rbac.Mapping{AdminGroup: cfg.AdminGroup, ViewerGroup: cfg.ViewerGroup},
		log:      log,
		pages:    map[string]*template.Template{},
	}
	funcs := template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.Format("2006-01-02 15:04:05 MST") },
	}
	for _, name := range []string{"home", "login", "dashboard", "admin", "error"} {
		t, err := template.New("layout.html").Funcs(funcs).
			ParseFS(assets, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return s, nil
}

// Sessions exposes the session manager (used by tests and auth handlers).
func (s *Server) Sessions() *session.Manager { return s.sessions }

// Handler returns the root HTTP handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)

	mux.Handle("GET /dashboard", s.requireRole(rbac.RoleViewer, http.HandlerFunc(s.handleDashboard)))
	mux.Handle("GET /admin", s.requireRole(rbac.RoleAdmin, http.HandlerFunc(s.handleAdmin)))

	// Later steps register here:
	//   /oidc/login, /oidc/callback            (step 3)
	//   /saml/metadata, /saml/acs, /saml/slo   (step 4)
	//   /scim/v2/Users, /scim/v2/Groups        (steps 5-6, bearer token, no session)

	return s.logRequests(securityHeaders(s.loadIdentity(mux)))
}
