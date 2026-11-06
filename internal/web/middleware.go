package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/audit"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/rbac"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/session"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

// Identity is the signed-in user for the current request.
type Identity struct {
	User       store.User
	Groups     []string
	Role       rbac.Role
	AuthMethod string
}

type ctxKey struct{}

// identityFrom returns the request's Identity, or nil if anonymous.
func identityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(ctxKey{}).(*Identity)
	return id
}

// loadIdentity resolves the session cookie to a user on every request.
//
// Roles are recomputed from the local group membership (kept current by
// SCIM) each time, rather than frozen from the login assertion, so a group
// change in Okta takes effect on the user's next request.
func (s *Server) loadIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.sessions.Current(r)
		if err != nil {
			if !errors.Is(err, session.ErrNoSession) {
				s.log.Error("session lookup", "err", err)
			}
			next.ServeHTTP(w, r)
			return
		}

		user, err := s.store.GetUser(r.Context(), sess.UserID)
		if err != nil || !user.Active {
			// Defence in depth: deactivation already deletes sessions, but if
			// one survived, kill it here too.
			_ = s.sessions.End(w, r)
			s.audit.Record(r.Context(), r, audit.SessionRevoked, "system", sess.UserID, audit.Success,
				map[string]any{"reason": "user inactive or missing"})
			next.ServeHTTP(w, r)
			return
		}

		groups, err := s.store.GroupNamesForUser(r.Context(), user.ID)
		if err != nil {
			s.log.Error("load groups", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		id := &Identity{User: user, Groups: groups, Role: s.roles.RoleFor(groups), AuthMethod: sess.AuthMethod}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

// requireRole enforces RBAC server-side. Anonymous users are sent to /login;
// signed-in users without the role get 403 and an audit event.
func (s *Server) requireRole(required rbac.Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identityFrom(r.Context())
		if id == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !id.Role.Satisfies(required) {
			s.audit.Record(r.Context(), r, audit.AccessDenied, id.User.UserName, r.URL.Path, audit.Failure,
				map[string]any{"role": id.Role.String(), "required": required.String()})
			s.renderError(w, r, http.StatusForbidden, "You don't have access to this page.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets conservative browser security headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// form-action allows posting to Okta for SAML/OIDC redirects added later.
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https:")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// logRequests writes one structured log line per request. It never logs
// headers, cookies or query strings, which can carry tokens.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"dur_ms", time.Since(start).Milliseconds())
	})
}
