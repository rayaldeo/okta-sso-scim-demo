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
	IDToken    string // OIDC only: raw ID token, used as id_token_hint at logout

	// SAML only: what Single Logout needs to name the IdP session.
	SAMLNameID       string
	SAMLSessionIndex string
}

// CreateSession stores a session under tokenHash.
func (s *Store) CreateSession(ctx context.Context, tokenHash string, sess Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions
		(token_hash, user_id, auth_method, created_ms, expires_ms, id_token, saml_name_id, saml_session_index)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tokenHash, sess.UserID, sess.AuthMethod, toMS(sess.Created), toMS(sess.Expires), sess.IDToken,
		sess.SAMLNameID, sess.SAMLSessionIndex)
	return err
}

// GetSession returns the unexpired session for tokenHash, or ErrNotFound.
func (s *Store) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	var created, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT user_id, auth_method, created_ms, expires_ms, id_token,
		saml_name_id, saml_session_index
		FROM sessions WHERE token_hash = ? AND expires_ms > ?`, tokenHash, toMS(s.now())).
		Scan(&sess.UserID, &sess.AuthMethod, &created, &expires, &sess.IDToken,
			&sess.SAMLNameID, &sess.SAMLSessionIndex)
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

// DeleteExpiredSessions purges expired sessions and login requests, and
// reports how many sessions were removed.
func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	now := toMS(s.now())
	for _, table := range []string{"login_requests", "saml_requests", "saml_assertions"} {
		// table names are constants, never user input
		if _, err := s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE expires_ms <= ?`, now); err != nil {
			return 0, err
		}
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_ms <= ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LoginRequest is the server-side half of an in-flight OIDC login.
type LoginRequest struct {
	Nonce        string
	PKCEVerifier string
	Expires      time.Time
}

// CreateLoginRequest stores an in-flight login under the hash of its state.
func (s *Store) CreateLoginRequest(ctx context.Context, stateHash string, lr LoginRequest) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO login_requests
		(state_hash, nonce, pkce_verifier, expires_ms) VALUES (?, ?, ?, ?)`,
		stateHash, lr.Nonce, lr.PKCEVerifier, toMS(lr.Expires))
	return err
}

// ConsumeLoginRequest deletes and returns the login request for stateHash.
// Because the row is deleted in the same statement, a state value can be
// used once only; a replayed callback gets ErrNotFound.
func (s *Store) ConsumeLoginRequest(ctx context.Context, stateHash string) (LoginRequest, error) {
	var lr LoginRequest
	var expires int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM login_requests WHERE state_hash = ?
		RETURNING nonce, pkce_verifier, expires_ms`, stateHash).
		Scan(&lr.Nonce, &lr.PKCEVerifier, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginRequest{}, ErrNotFound
	}
	if err != nil {
		return LoginRequest{}, err
	}
	lr.Expires = fromMS(expires)
	if !lr.Expires.After(s.now()) {
		return LoginRequest{}, ErrNotFound
	}
	return lr, nil
}
