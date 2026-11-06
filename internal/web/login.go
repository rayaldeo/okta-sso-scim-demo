package web

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/audit"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

// loginIdentity is what a verified SAML assertion or OIDC ID token tells us
// about the user. Both protocols are mapped to this one shape so that
// account matching, JIT provisioning and session creation are shared.
type loginIdentity struct {
	Method      string // "oidc" or "saml"
	Subject     string // IdP's stable user ID
	UserName    string
	Email       string
	GivenName   string
	FamilyName  string
	DisplayName string
	Groups      []string
	HasGroups   bool // the IdP sent a groups attribute/claim (possibly empty)
	IDToken     string
}

var (
	errNoUserName      = errors.New("identity has no username")
	errNotProvisioned  = errors.New("user is not provisioned in this app")
	errUserDeactivated = errors.New("user is deactivated")
)

// resolveUser maps a verified identity to a local account.
//
// With JIT provisioning on, the first sign-in creates the account, and each
// sign-in refreshes profile and group membership from the token. With it
// off, accounts must already exist (created by SCIM) and sign-in only
// authenticates: the app never lets a login token create or elevate a user.
func (s *Server) resolveUser(ctx context.Context, r *http.Request, li loginIdentity) (store.User, error) {
	li.UserName = strings.TrimSpace(li.UserName)
	if li.UserName == "" {
		return store.User{}, errNoUserName
	}

	u, err := s.store.GetUserByUserName(ctx, li.UserName)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if !s.cfg.JITProvisioning {
			return store.User{}, errNotProvisioned
		}
		u = store.User{
			UserName: li.UserName, ExternalID: li.Subject, Email: li.Email,
			GivenName: li.GivenName, FamilyName: li.FamilyName, DisplayName: li.DisplayName,
			Active: true,
		}
		if err := s.store.CreateUser(ctx, &u); err != nil {
			return store.User{}, err
		}
		s.audit.Record(ctx, r, audit.JITProvision, li.Method, u.UserName, audit.Success,
			map[string]any{"sub": li.Subject})
	case err != nil:
		return store.User{}, err
	case !u.Active:
		return store.User{}, errUserDeactivated
	case s.cfg.JITProvisioning:
		u.ExternalID, u.Email = li.Subject, li.Email
		u.GivenName, u.FamilyName, u.DisplayName = li.GivenName, li.FamilyName, li.DisplayName
		if err := s.store.UpdateUserProfile(ctx, &u); err != nil {
			return store.User{}, err
		}
	}

	// Only replace memberships when the IdP actually sent a groups claim;
	// a missing claim (misconfigured filter) must not silently strip roles.
	if s.cfg.JITProvisioning && li.HasGroups {
		if err := s.store.SetUserGroups(ctx, u.ID, li.Groups); err != nil {
			return store.User{}, err
		}
	}
	return u, nil
}

// completeLogin resolves the user, starts a session and redirects to the
// dashboard, or renders a failure. Every outcome is audited.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, li loginIdentity) {
	ctx := r.Context()
	u, err := s.resolveUser(ctx, r, li)
	if err != nil {
		s.loginFailed(w, r, li.Method, li.UserName, err)
		return
	}
	if err := s.sessions.Start(ctx, w, r, u.ID, li.Method, li.IDToken); err != nil {
		s.loginFailed(w, r, li.Method, li.UserName, err)
		return
	}
	s.audit.Record(ctx, r, audit.LoginSuccess, u.UserName, u.UserName, audit.Success,
		map[string]any{"method": li.Method, "sub": li.Subject})
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// loginFailed audits the real reason but shows the user a short message,
// so error pages don't leak protocol detail to an attacker probing the flow.
func (s *Server) loginFailed(w http.ResponseWriter, r *http.Request, method, who string, err error) {
	s.audit.Record(r.Context(), r, audit.LoginFailure, who, who, audit.Failure,
		map[string]any{"method": method, "reason": err.Error()})

	status, msg := http.StatusBadRequest, "Sign-in failed. Please try again."
	switch {
	case errors.Is(err, errNotProvisioned):
		status, msg = http.StatusForbidden, "Your account hasn't been provisioned to this app yet. Ask an admin to assign it in Okta."
	case errors.Is(err, errUserDeactivated):
		status, msg = http.StatusForbidden, "Your account in this app is deactivated."
	}
	s.renderError(w, r, status, msg)
}
