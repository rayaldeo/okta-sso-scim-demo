package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSAMLRequestIsSingleUseAndKindChecked(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	now := time.Now()
	s.SetClock(func() time.Time { return now })

	_ = s.CreateSAMLRequest(ctx, "r1", SAMLAuthn, "id-1", now.Add(time.Minute))
	id, err := s.ConsumeSAMLRequest(ctx, "r1", SAMLAuthn)
	if err != nil || id != "id-1" {
		t.Fatalf("first consume: %q %v", id, err)
	}
	if _, err := s.ConsumeSAMLRequest(ctx, "r1", SAMLAuthn); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay should be ErrNotFound, got %v", err)
	}

	// A logout RelayState can't be used to complete a login.
	_ = s.CreateSAMLRequest(ctx, "r2", SAMLLogout, "id-2", now.Add(time.Minute))
	if _, err := s.ConsumeSAMLRequest(ctx, "r2", SAMLAuthn); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong kind should be ErrNotFound, got %v", err)
	}

	_ = s.CreateSAMLRequest(ctx, "r3", SAMLAuthn, "id-3", now.Add(time.Minute))
	s.SetClock(func() time.Time { return now.Add(2 * time.Minute) })
	if _, err := s.ConsumeSAMLRequest(ctx, "r3", SAMLAuthn); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired request should be ErrNotFound, got %v", err)
	}
}

func TestAssertionIDCanOnlyBeConsumedOnce(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	exp := time.Now().Add(time.Minute)
	if err := s.ConsumeAssertionID(ctx, "a1", exp); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeAssertionID(ctx, "a1", exp); !errors.Is(err, ErrAlreadyUsed) {
		t.Fatalf("second use should be ErrAlreadyUsed, got %v", err)
	}
}

func TestSessionKeepsSAMLLogoutDetails(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	u := &User{UserName: "sam@example.com", Active: true}
	_ = s.CreateUser(ctx, u)
	now := time.Now()
	_ = s.CreateSession(ctx, "h", Session{UserID: u.ID, AuthMethod: "saml", Created: now,
		Expires: now.Add(time.Hour), SAMLNameID: "sam@example.com", SAMLSessionIndex: "idx-1"})
	got, err := s.GetSession(ctx, "h")
	if err != nil || got.SAMLNameID != "sam@example.com" || got.SAMLSessionIndex != "idx-1" {
		t.Fatalf("got %+v %v", got, err)
	}
}
