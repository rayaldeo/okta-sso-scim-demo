package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SAML message kinds stored in saml_requests.
const (
	SAMLAuthn  = "authn"
	SAMLLogout = "logout"
)

// CreateSAMLRequest records the ID of a SAML request we sent, keyed by the
// hash of the RelayState that travels with it.
func (s *Store) CreateSAMLRequest(ctx context.Context, relayHash, kind, requestID string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO saml_requests
		(relay_hash, kind, request_id, expires_ms) VALUES (?, ?, ?, ?)`,
		relayHash, kind, requestID, toMS(expires))
	return err
}

// ConsumeSAMLRequest deletes and returns the request ID for relayHash. It
// returns ErrNotFound if there is none, it has expired, or it is of a
// different kind; any of those means the response is unsolicited or replayed.
func (s *Store) ConsumeSAMLRequest(ctx context.Context, relayHash, kind string) (string, error) {
	var id, gotKind string
	var expires int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM saml_requests WHERE relay_hash = ?
		RETURNING kind, request_id, expires_ms`, relayHash).Scan(&gotKind, &id, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if gotKind != kind || !fromMS(expires).After(s.now()) {
		return "", ErrNotFound
	}
	return id, nil
}

// ErrAlreadyUsed means an assertion ID has been accepted before.
var ErrAlreadyUsed = errors.New("already used")

// ConsumeAssertionID records a SAML assertion ID as used until expiresAt.
// It returns ErrAlreadyUsed if the ID was recorded before.
func (s *Store) ConsumeAssertionID(ctx context.Context, assertionID string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO saml_assertions (assertion_id, expires_ms) VALUES (?, ?)`,
		assertionID, toMS(expiresAt))
	if isUniqueViolation(err) {
		return ErrAlreadyUsed
	}
	return err
}
