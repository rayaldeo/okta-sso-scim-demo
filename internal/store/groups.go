package store

import (
	"context"
	"time"
)

// Group mirrors an Okta group pushed to the app.
type Group struct {
	ID          string
	ExternalID  string
	DisplayName string
	Created     time.Time
	Updated     time.Time
}

// CreateGroup inserts g, assigning ID and timestamps. displayName is unique
// case-insensitively; a duplicate returns ErrConflict.
func (s *Store) CreateGroup(ctx context.Context, g *Group) error {
	now := s.now().UTC()
	g.ID, g.Created, g.Updated = newID(), now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO groups
		(id, external_id, display_name, created_ms, updated_ms) VALUES (?, ?, ?, ?, ?)`,
		g.ID, g.ExternalID, g.DisplayName, toMS(now), toMS(now))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// AddGroupMember adds userID to groupID. Adding an existing member is a no-op.
func (s *Store) AddGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`, groupID, userID)
	return err
}

// RemoveGroupMember removes userID from groupID. Removing a non-member is a no-op.
func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, groupID, userID)
	return err
}

// GroupNamesForUser returns the display names of every group userID belongs to.
func (s *Store) GroupNamesForUser(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.display_name FROM groups g
		JOIN group_members m ON m.group_id = g.id
		WHERE m.user_id = ? ORDER BY g.display_name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}
