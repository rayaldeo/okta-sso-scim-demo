package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUserNameIsUniqueCaseInsensitive(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()

	if err := s.CreateUser(ctx, &User{UserName: "alice@example.com", Active: true}); err != nil {
		t.Fatal(err)
	}
	err := s.CreateUser(ctx, &User{UserName: "ALICE@example.com", Active: true})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}

	got, err := s.GetUserByUserName(ctx, "Alice@Example.com")
	if err != nil || got.UserName != "alice@example.com" {
		t.Fatalf("lookup: %+v %v", got, err)
	}
}

func TestGetMissingUser(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetUser(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestDeactivateRevokesSessions(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	u := &User{UserName: "bob@example.com", Active: true}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.CreateSession(ctx, "h1", Session{UserID: u.ID, AuthMethod: "oidc",
		Created: now, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	if err := s.SetUserActive(ctx, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session should be gone after deactivation, got %v", err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.Active || got.Version != 2 {
		t.Fatalf("want inactive v2, got active=%v v%d", got.Active, got.Version)
	}
}

func TestSessionExpiry(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	u := &User{UserName: "carol@example.com", Active: true}
	_ = s.CreateUser(ctx, u)

	now := time.Now()
	s.SetClock(func() time.Time { return now })
	_ = s.CreateSession(ctx, "h", Session{UserID: u.ID, AuthMethod: "saml", Created: now, Expires: now.Add(time.Minute)})

	if _, err := s.GetSession(ctx, "h"); err != nil {
		t.Fatalf("fresh session: %v", err)
	}
	s.SetClock(func() time.Time { return now.Add(2 * time.Minute) })
	if _, err := s.GetSession(ctx, "h"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session should be ErrNotFound, got %v", err)
	}
	if n, _ := s.DeleteExpiredSessions(ctx); n != 1 {
		t.Fatalf("want 1 purged, got %d", n)
	}
}

func TestGroupMembership(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	u := &User{UserName: "dan@example.com", Active: true}
	_ = s.CreateUser(ctx, u)
	admins, viewers := &Group{DisplayName: "app-admin"}, &Group{DisplayName: "app-viewer"}
	_ = s.CreateGroup(ctx, admins)
	_ = s.CreateGroup(ctx, viewers)

	_ = s.AddGroupMember(ctx, viewers.ID, u.ID)
	_ = s.AddGroupMember(ctx, admins.ID, u.ID)
	_ = s.AddGroupMember(ctx, admins.ID, u.ID) // idempotent

	names, err := s.GroupNamesForUser(ctx, u.ID)
	if err != nil || len(names) != 2 || names[0] != "app-admin" {
		t.Fatalf("got %v %v", names, err)
	}

	_ = s.RemoveGroupMember(ctx, admins.ID, u.ID)
	names, _ = s.GroupNamesForUser(ctx, u.ID)
	if len(names) != 1 || names[0] != "app-viewer" {
		t.Fatalf("after remove got %v", names)
	}

	if err := s.CreateGroup(ctx, &Group{DisplayName: "APP-ADMIN"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict for duplicate group, got %v", err)
	}
}

func TestAuditNewestFirst(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	for _, typ := range []string{"a", "b", "c"} {
		if err := s.InsertAudit(ctx, AuditEvent{Type: typ, Outcome: "success"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListAudit(ctx, 2)
	if err != nil || len(got) != 2 || got[0].Type != "c" || got[1].Type != "b" {
		t.Fatalf("got %+v %v", got, err)
	}
}
