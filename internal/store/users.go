package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// User is the app's local copy of an identity. In normal operation Okta is
// the source of truth and writes these rows through SCIM.
type User struct {
	ID          string
	ExternalID  string
	UserName    string
	GivenName   string
	FamilyName  string
	DisplayName string
	Email       string
	Active      bool
	Created     time.Time
	Updated     time.Time
	Version     int
}

const userCols = `id, external_id, user_name, given_name, family_name, display_name,
	email, active, created_ms, updated_ms, version`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var created, updated int64
	err := row.Scan(&u.ID, &u.ExternalID, &u.UserName, &u.GivenName, &u.FamilyName,
		&u.DisplayName, &u.Email, &u.Active, &created, &updated, &u.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.Created, u.Updated = fromMS(created), fromMS(updated)
	return u, nil
}

// CreateUser inserts u, assigning ID, timestamps and version. userName is
// unique case-insensitively; a duplicate returns ErrConflict.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	now := s.now().UTC()
	u.ID, u.Created, u.Updated, u.Version = newID(), now, now, 1
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (`+userCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.ExternalID, u.UserName, u.GivenName, u.FamilyName, u.DisplayName,
		u.Email, u.Active, toMS(now), toMS(now), u.Version)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// GetUser returns the user with the given ID.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// GetUserByUserName looks a user up by userName (case-insensitive).
func (s *Store) GetUserByUserName(ctx context.Context, userName string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE user_name = ?`, userName))
}

// ListUsers returns all users ordered by userName.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY user_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserActive activates or deactivates a user. Deactivating a user also
// deletes all of their sessions in the same transaction, so access ends
// immediately rather than when the session would have expired.
func (s *Store) SetUserActive(ctx context.Context, id string, active bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE users SET active = ?, updated_ms = ?, version = version + 1 WHERE id = ?`,
		active, toMS(s.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if !active {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
