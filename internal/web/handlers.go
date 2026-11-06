package web

import (
	"bytes"
	"net/http"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/audit"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

type pageData struct {
	Title    string
	Identity *Identity
	Data     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page, title string, data any) {
	var buf bytes.Buffer
	pd := pageData{Title: title, Identity: identityFrom(r.Context()), Data: data}
	if err := s.pages[page].ExecuteTemplate(&buf, "layout.html", pd); err != nil {
		s.log.Error("render", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.render(w, r, status, "error", http.StatusText(status),
		map[string]any{"Status": status, "Message": msg})
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "home", "Home", nil)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if identityFrom(r.Context()) != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", "Sign in", map[string]any{
		"OIDC": s.cfg.OIDCEnabled(),
		"SAML": s.cfg.SAMLEnabled(),
	})
}

// handleLogout ends the local session. Steps 3-4 extend this to also end the
// Okta session (OIDC RP-initiated logout / SAML Single Logout).
// It is POST-only: combined with SameSite=Lax cookies, other sites can't log
// a user out by embedding a link or image.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if id := identityFrom(r.Context()); id != nil {
		s.audit.Record(r.Context(), r, audit.Logout, id.User.UserName, id.User.UserName, audit.Success,
			map[string]any{"method": id.AuthMethod})
	}
	if err := s.sessions.End(w, r); err != nil {
		s.log.Error("end session", "err", err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "dashboard", "Dashboard", nil)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not load users.")
		return
	}
	events, err := s.store.ListAudit(ctx, 100)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not load audit log.")
		return
	}
	s.render(w, r, http.StatusOK, "admin", "Admin", struct {
		Users  []store.User
		Events []store.AuditEvent
	}{users, events})
}
