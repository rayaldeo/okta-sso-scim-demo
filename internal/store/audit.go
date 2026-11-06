package store

import (
	"context"
	"time"
)

// AuditEvent is one append-only audit log row.
type AuditEvent struct {
	ID      int64
	Time    time.Time
	Type    string // e.g. "login.success", "scim.user.deactivate"
	Actor   string // who did it: a userName, or "okta-scim"
	Subject string // who/what it was done to
	Outcome string // "success" or "failure"
	Detail  string // JSON object with extra context
	IP      string
}

// InsertAudit appends an event. Time defaults to now.
func (s *Store) InsertAudit(ctx context.Context, e AuditEvent) error {
	if e.Time.IsZero() {
		e.Time = s.now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events
		(ts_ms, event_type, actor, subject, outcome, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		toMS(e.Time), e.Type, e.Actor, e.Subject, e.Outcome, e.Detail, e.IP)
	return err
}

// ListAudit returns the most recent events, newest first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts_ms, event_type, actor, subject,
		outcome, detail, ip FROM audit_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Type, &e.Actor, &e.Subject,
			&e.Outcome, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		e.Time = fromMS(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
