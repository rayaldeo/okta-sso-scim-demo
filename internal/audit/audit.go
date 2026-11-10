// Package audit records security-relevant events to the database and to the
// structured application log.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

// Event types. Keep these stable: they are what you'd alert on in a SIEM.
const (
	LoginSuccess     = "login.success"
	LoginFailure     = "login.failure"
	JITProvision     = "login.jit_provision"
	Logout           = "logout"
	IdPLogout        = "logout.idp_response"
	AccessDenied     = "authz.denied"
	SessionRevoked   = "session.revoked"
	SCIMAuthFailure  = "scim.auth.failure"
	SCIMUserCreate   = "scim.user.create"
	SCIMUserUpdate   = "scim.user.update"
	SCIMUserActivate = "scim.user.activate"
	SCIMUserDeactiv  = "scim.user.deactivate"
	SCIMGroupCreate  = "scim.group.create"
	SCIMGroupUpdate  = "scim.group.update"
	SCIMGroupDelete  = "scim.group.delete"
)

// Outcomes.
const (
	Success = "success"
	Failure = "failure"
)

// Logger writes audit events.
type Logger struct {
	store *store.Store
	log   *slog.Logger
}

// New returns a Logger.
func New(st *store.Store, log *slog.Logger) *Logger { return &Logger{store: st, log: log} }

// Record writes an event. r may be nil for events not tied to a request.
// Failures to write the audit row are logged but never break the request:
// for a demo that is the right trade-off; a regulated system might fail closed.
func (l *Logger) Record(ctx context.Context, r *http.Request, typ, actor, subject, outcome string, detail map[string]any) {
	e := store.AuditEvent{Type: typ, Actor: actor, Subject: subject, Outcome: outcome, IP: clientIP(r)}
	if len(detail) > 0 {
		if b, err := json.Marshal(detail); err == nil {
			e.Detail = string(b)
		}
	}
	if err := l.store.InsertAudit(ctx, e); err != nil {
		l.log.Error("audit write failed", "type", typ, "err", err)
	}
	l.log.Info("audit", "type", typ, "actor", actor, "subject", subject, "outcome", outcome, "ip", e.IP)
}

// clientIP returns the TCP peer address. X-Forwarded-For is deliberately
// ignored: it is client-controlled unless a trusted proxy sets it.
func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
