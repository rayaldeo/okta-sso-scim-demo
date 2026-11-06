// Package session implements server-side sessions backed by the store.
//
// The browser gets a 256-bit random token in an HttpOnly, SameSite=Lax cookie
// (with the __Host- prefix over HTTPS). The database stores only the token's
// SHA-256 hash, so sessions can be revoked server-side at any time, e.g. when
// Okta deprovisions a user over SCIM.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

// Manager issues, reads and ends sessions.
type Manager struct {
	store  *store.Store
	ttl    time.Duration
	secure bool
	now    func() time.Time
}

// New returns a Manager. secure should be true whenever the app is on HTTPS.
func New(st *store.Store, ttl time.Duration, secure bool) *Manager {
	return &Manager{store: st, ttl: ttl, secure: secure, now: time.Now}
}

// CookieName is the session cookie name. The __Host- prefix makes browsers
// refuse the cookie unless it is Secure, Path=/ and has no Domain, which
// blocks subdomain cookie-injection attacks. It needs HTTPS, so plain-HTTP
// local development uses a regular name.
func (m *Manager) CookieName() string {
	if m.secure {
		return "__Host-sid"
	}
	return "sid"
}

// Start creates a new session for userID and sets the cookie. Any session the
// request already carried is destroyed first (prevents session fixation).
// idToken is the raw OIDC ID token ("" for SAML), kept for logout.
func (m *Manager) Start(ctx context.Context, w http.ResponseWriter, r *http.Request, userID, method, idToken string) error {
	if r != nil {
		if c, err := r.Cookie(m.CookieName()); err == nil {
			_ = m.store.DeleteSession(ctx, hashToken(c.Value))
		}
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := m.now().UTC()
	expires := now.Add(m.ttl)

	if err := m.store.CreateSession(ctx, hashToken(token), store.Session{
		UserID: userID, AuthMethod: method, Created: now, Expires: expires, IDToken: idToken,
	}); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(m.ttl.Seconds()),
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode, // Lax (not Strict) so the SSO redirect back from Okta keeps the cookie
	})
	return nil
}

// ErrNoSession means the request has no valid session.
var ErrNoSession = errors.New("no session")

// Current returns the session attached to r, if it is valid and unexpired.
func (m *Manager) Current(r *http.Request) (store.Session, error) {
	c, err := r.Cookie(m.CookieName())
	if err != nil || c.Value == "" {
		return store.Session{}, ErrNoSession
	}
	sess, err := m.store.GetSession(r.Context(), hashToken(c.Value))
	if errors.Is(err, store.ErrNotFound) {
		return store.Session{}, ErrNoSession
	}
	return sess, err
}

// End destroys the session attached to r (if any) and clears the cookie.
func (m *Manager) End(w http.ResponseWriter, r *http.Request) error {
	var err error
	if c, cerr := r.Cookie(m.CookieName()); cerr == nil {
		err = m.store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	m.clearCookie(w)
	return err
}

func (m *Manager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: m.CookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode,
	})
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
