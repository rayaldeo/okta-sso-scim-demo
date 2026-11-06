// Package auth holds the protocol clients that talk to the identity provider.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig configures the OIDC relying party (this app).
type OIDCConfig struct {
	Issuer       string // e.g. https://integrator-123.okta.com
	ClientID     string
	ClientSecret string
	RedirectURL  string // must exactly match a sign-in redirect URI in Okta
	Scopes       []string
}

// OIDC implements the authorization code flow with PKCE.
type OIDC struct {
	ctx        context.Context // carries the HTTP client used for discovery, JWKS and token calls
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	endSession string
}

// NewOIDC runs OIDC discovery against the issuer
// (<issuer>/.well-known/openid-configuration) and prepares the client.
// go-oidc checks that the discovered "issuer" matches cfg.Issuer exactly,
// which stops a tampered discovery document from swapping in another issuer.
func NewOIDC(cfg OIDCConfig) (*OIDC, error) {
	// A long-lived context with an HTTP client that has a timeout. go-oidc
	// keeps this context to refresh signing keys (JWKS) later, so it must not
	// be a request context that gets cancelled.
	ctx := oidc.ClientContext(context.Background(), &http.Client{Timeout: 10 * time.Second})

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.Issuer, err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("read discovery metadata: %w", err)
	}

	return &OIDC{
		ctx: ctx,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
		},
		// Verifies signature (against the IdP's JWKS), issuer, audience
		// (must contain our client ID) and expiry. Only RS256 is accepted.
		verifier:   provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		endSession: meta.EndSession,
	}, nil
}

// AuthRequest is everything needed to start one login.
type AuthRequest struct {
	State        string // random; ties the callback to this browser (CSRF defence)
	Nonce        string // random; must come back inside the ID token (replay defence)
	PKCEVerifier string // random; proves the token request comes from whoever started the login
	URL          string // where to send the browser
}

// NewAuthRequest generates fresh state, nonce and PKCE verifier and builds
// the authorization URL. Only the S256 challenge (a hash of the verifier)
// leaves the server.
func (o *OIDC) NewAuthRequest() (AuthRequest, error) {
	state, err := randomString()
	if err != nil {
		return AuthRequest{}, err
	}
	nonce, err := randomString()
	if err != nil {
		return AuthRequest{}, err
	}
	verifier := oauth2.GenerateVerifier()
	return AuthRequest{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		URL:          o.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)),
	}, nil
}

// Claims are the identity attributes taken from a verified ID token.
type Claims struct {
	Subject           string // Okta user ID, stable even if the username changes
	PreferredUsername string // Okta login
	Email             string
	EmailVerified     bool
	Name              string
	GivenName         string
	FamilyName        string
	Groups            []string
	HasGroupsClaim    bool   // false if Okta sent no groups claim at all
	RawIDToken        string // kept for id_token_hint at logout
}

// ErrNonceMismatch means the ID token was not issued for this login.
var ErrNonceMismatch = errors.New("id token nonce does not match")

// Exchange swaps the authorization code for tokens (sending the PKCE
// verifier and client secret), then verifies the ID token and its nonce.
func (o *OIDC) Exchange(ctx context.Context, code, pkceVerifier, nonce string) (Claims, error) {
	ctx = mergeClient(ctx, o.ctx)

	tok, err := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return Claims{}, fmt.Errorf("token exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Claims{}, errors.New("token response has no id_token")
	}
	idt, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return Claims{}, fmt.Errorf("verify id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		return Claims{}, ErrNonceMismatch
	}

	var c struct {
		Email             string    `json:"email"`
		EmailVerified     bool      `json:"email_verified"`
		Name              string    `json:"name"`
		GivenName         string    `json:"given_name"`
		FamilyName        string    `json:"family_name"`
		PreferredUsername string    `json:"preferred_username"`
		Groups            *[]string `json:"groups"`
	}
	if err := idt.Claims(&c); err != nil {
		return Claims{}, fmt.Errorf("decode claims: %w", err)
	}
	out := Claims{
		Subject:           idt.Subject,
		PreferredUsername: c.PreferredUsername,
		Email:             c.Email,
		EmailVerified:     c.EmailVerified,
		Name:              c.Name,
		GivenName:         c.GivenName,
		FamilyName:        c.FamilyName,
		RawIDToken:        raw,
	}
	if c.Groups != nil {
		out.Groups, out.HasGroupsClaim = *c.Groups, true
	}
	return out, nil
}

// LogoutURL returns the IdP's RP-initiated logout URL, or "" if the IdP
// doesn't advertise one. Okta requires id_token_hint, and redirects back to
// postLogout only if it is registered as a sign-out redirect URI.
func (o *OIDC) LogoutURL(idToken, postLogout string) string {
	if o.endSession == "" || idToken == "" {
		return ""
	}
	u, err := url.Parse(o.endSession)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("id_token_hint", idToken)
	q.Set("post_logout_redirect_uri", postLogout)
	u.RawQuery = q.Encode()
	return u.String()
}

// mergeClient makes the request context use the configured HTTP client while
// still honouring the request's cancellation.
func mergeClient(req, base context.Context) context.Context {
	if c, ok := base.Value(oauth2.HTTPClient).(*http.Client); ok {
		return oidc.ClientContext(req, c)
	}
	return req
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
