package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/audit"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

// The state value lives in a short-lived cookie scoped to /oidc/, and its
// hash keys the server-side row holding the nonce and PKCE verifier.
const (
	oidcStateCookie = "oidc_state"
	loginRequestTTL = 10 * time.Minute
)

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// handleOIDCLogin starts the authorization code flow: it stores the nonce
// and PKCE verifier server-side, binds the state to this browser with a
// cookie, and redirects to Okta's /authorize endpoint.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	ar, err := s.oidc.NewAuthRequest()
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not start sign-in.")
		return
	}
	if err := s.store.CreateLoginRequest(r.Context(), hashString(ar.State), store.LoginRequest{
		Nonce: ar.Nonce, PKCEVerifier: ar.PKCEVerifier, Expires: time.Now().Add(loginRequestTTL),
	}); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not start sign-in.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: ar.State, Path: "/oidc/",
		MaxAge: int(loginRequestTTL.Seconds()), HttpOnly: true,
		Secure: s.cfg.SecureCookies(), SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, ar.URL, http.StatusFound)
}

// handleOIDCCallback finishes the flow. Checks, in order:
//  1. Okta didn't return an error (e.g. user not assigned to the app).
//  2. The state in the URL matches this browser's state cookie (login CSRF).
//  3. The state maps to an unexpired, unused login request (replay).
//  4. Code exchange with PKCE verifier + client secret succeeds.
//  5. ID token signature, issuer, audience, expiry and nonce all verify.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// The state cookie is one-shot whatever happens next.
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: "", Path: "/oidc/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.SecureCookies(), SameSite: http.SameSiteLaxMode,
	})

	if e := q.Get("error"); e != "" {
		// Okta-supplied text; html/template escapes it when rendered.
		s.audit.Record(r.Context(), r, audit.LoginFailure, "", "", audit.Failure,
			map[string]any{"method": "oidc", "reason": "idp error: " + e, "description": q.Get("error_description")})
		s.renderError(w, r, http.StatusForbidden, "Okta did not sign you in: "+strings.TrimSpace(q.Get("error_description")))
		return
	}

	state := q.Get("state")
	c, err := r.Cookie(oidcStateCookie)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		s.loginFailed(w, r, "oidc", "", errors.New("state mismatch"))
		return
	}
	lr, err := s.store.ConsumeLoginRequest(r.Context(), hashString(state))
	if err != nil {
		s.loginFailed(w, r, "oidc", "", errors.New("unknown, expired or reused login request"))
		return
	}

	claims, err := s.oidc.Exchange(r.Context(), q.Get("code"), lr.PKCEVerifier, lr.Nonce)
	if err != nil {
		s.loginFailed(w, r, "oidc", "", err)
		return
	}

	userName := claims.PreferredUsername
	if userName == "" {
		userName = claims.Email
	}
	display := claims.Name
	if display == "" {
		display = strings.TrimSpace(claims.GivenName + " " + claims.FamilyName)
	}
	s.completeLogin(w, r, loginIdentity{
		Method: "oidc", Subject: claims.Subject, UserName: userName, Email: claims.Email,
		GivenName: claims.GivenName, FamilyName: claims.FamilyName, DisplayName: display,
		Groups: claims.Groups, HasGroups: claims.HasGroupsClaim, IDToken: claims.RawIDToken,
	})
}
