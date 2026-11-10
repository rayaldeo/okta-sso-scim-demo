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
	"github.com/rayaldeo/okta-sso-scim-demo/internal/auth"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/config"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/rbac"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/session"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Options are optional components. A nil protocol client disables that
// sign-in method.
type Options struct {
	OIDC *auth.OIDC
	SAML *auth.SAML
}

// Server holds the app's dependencies.
type Server struct {
	cfg      config.Config
	store    *store.Store
	sessions *session.Manager
	audit    *audit.Logger
	roles    rbac.Mapping
	log      *slog.Logger
	pages    map[string]*template.Template
	oidc     *auth.OIDC
	saml     *auth.SAML
}

// New builds a Server and parses its templates.
func New(cfg config.Config, st *store.Store, log *slog.Logger, opts Options) (*Server, error) {
	s := &Server{
		cfg:      cfg,
		store:    st,
		sessions: session.New(st, cfg.SessionTTL, cfg.SecureCookies()),
		audit:    audit.New(st, log),
		roles:    rbac.Mapping{AdminGroup: cfg.AdminGroup, ViewerGroup: cfg.ViewerGroup},
		log:      log,
		pages:    map[string]*template.Template{},
		oidc:     opts.OIDC,
		saml:     opts.SAML,
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

	if s.oidc != nil {
		mux.HandleFunc("GET /oidc/login", s.handleOIDCLogin)
		mux.HandleFunc("GET /oidc/callback", s.handleOIDCCallback)
	}

	if s.saml != nil {
		mux.HandleFunc("GET /saml/metadata", s.handleSAMLMetadata)
		mux.HandleFunc("GET /saml/login", s.handleSAMLLogin)
		mux.HandleFunc("POST /saml/acs", s.handleSAMLACS)
		mux.HandleFunc("GET /saml/slo", s.handleSAMLSLO)
		mux.HandleFunc("POST /saml/slo", s.handleSAMLSLO)
	}

	// Later steps register here:
	//   /scim/v2/Users, /scim/v2/Groups        (steps 5-6, bearer token, no session)

	return s.logRequests(securityHeaders(s.loadIdentity(mux)))
}
