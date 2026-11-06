package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Session is a server-side login session. The cookie holds a random token;
// the database holds only its hash.
type Session struct {
	UserID     string
	AuthMethod string // "saml" or "oidc"
	Created    time.Time
	Expires    time.Time
}

// CreateSession stores a session under tokenHash.
func (s *Store) CreateSession(ctx context.Context, tokenHash string, sess Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions
		(token_hash, user_id, auth_method, created_ms, expires_ms) VALUES (?, ?, ?, ?, ?)`,
		tokenHash, sess.UserID, sess.AuthMethod, toMS(sess.Created), toMS(sess.Expires))
	return err
}

// GetSession returns the unexpired session for tokenHash, or ErrNotFound.
func (s *Store) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	var created, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT user_id, auth_method, created_ms, expires_ms
		FROM sessions WHERE token_hash = ? AND expires_ms > ?`, tokenHash, toMS(s.now())).
		Scan(&sess.UserID, &sess.AuthMethod, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	sess.Created, sess.Expires = fromMS(created), fromMS(expires)
	return sess, nil
}

// DeleteSession removes one session. Deleting a missing session is a no-op.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteSessionsForUser revokes every session for userID and reports how many.
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteExpiredSessions purges expired rows and reports how many.
func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_ms <= ?`, toMS(s.now()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
