// Package store persists users, groups, sessions and audit events in SQLite.
//
// It uses modernc.org/sqlite (pure Go, no cgo) so the app builds the same on
// Windows, Linux and in a scratch container.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound means the requested row does not exist (or has expired).
	ErrNotFound = errors.New("not found")
	// ErrConflict means a uniqueness rule (e.g. userName) was violated.
	ErrConflict = errors.New("conflict")
)

// Store wraps the database handle.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the SQLite database at path and applies the
// schema. Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	var dsn string
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(1)"
	} else {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
		dsn = "file:" + filepath.ToSlash(path) +
			"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite serialises writes anyway, and it keeps an
	// in-memory test database shared across calls. Fine for a demo; see
	// README "production hardening" for the Postgres path.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, now: time.Now}
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// migrate applies additive changes to databases created by older versions.
func (s *Store) migrate(ctx context.Context) error {
	return s.addColumnIfMissing(ctx, "sessions", "id_token", "TEXT NOT NULL DEFAULT ''")
}

func (s *Store) addColumnIfMissing(ctx context.Context, table, column, decl string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	// table/column/decl are constants from this file, never user input.
	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, decl))
	return err
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SetClock overrides the time source (tests only).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id           TEXT PRIMARY KEY,
	external_id  TEXT NOT NULL DEFAULT '',
	user_name    TEXT NOT NULL UNIQUE COLLATE NOCASE,
	given_name   TEXT NOT NULL DEFAULT '',
	family_name  TEXT NOT NULL DEFAULT '',
	display_name TEXT NOT NULL DEFAULT '',
	email        TEXT NOT NULL DEFAULT '',
	active       INTEGER NOT NULL DEFAULT 1,
	created_ms   INTEGER NOT NULL,
	updated_ms   INTEGER NOT NULL,
	version      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS groups (
	id           TEXT PRIMARY KEY,
	external_id  TEXT NOT NULL DEFAULT '',
	display_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
	created_ms   INTEGER NOT NULL,
	updated_ms   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
	group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
	user_id  TEXT NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
	PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

-- Only a SHA-256 hash of the session token is stored, so a copy of the
-- database cannot be replayed as live cookies.
CREATE TABLE IF NOT EXISTS sessions (
	token_hash  TEXT PRIMARY KEY,
	user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	auth_method TEXT NOT NULL,
	created_ms  INTEGER NOT NULL,
	expires_ms  INTEGER NOT NULL,
	-- Kept only to send as id_token_hint on OIDC logout.
	id_token    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- In-flight OIDC logins: state (hashed) -> nonce + PKCE verifier. Single use,
-- deleted on callback, expire after a few minutes.
CREATE TABLE IF NOT EXISTS login_requests (
	state_hash    TEXT PRIMARY KEY,
	nonce         TEXT NOT NULL,
	pkce_verifier TEXT NOT NULL,
	expires_ms    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts_ms      INTEGER NOT NULL,
	event_type TEXT NOT NULL,
	actor      TEXT NOT NULL DEFAULT '',
	subject    TEXT NOT NULL DEFAULT '',
	outcome    TEXT NOT NULL,
	detail     TEXT NOT NULL DEFAULT '',
	ip         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts_ms);
`

func toMS(t time.Time) int64    { return t.UnixMilli() }
func fromMS(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

// newID returns a random RFC 4122 version 4 UUID.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
