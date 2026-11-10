package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rayaldeo/okta-sso-scim-demo/internal/audit"
	"github.com/rayaldeo/okta-sso-scim-demo/internal/store"
)

const samlRequestTTL = 10 * time.Minute

// handleSAMLMetadata serves this SP's metadata. Okta doesn't need it (you
// type the URLs in), but it documents the setup and other IdPs can import it.
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	md, err := s.saml.Metadata()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(md)
}

// handleSAMLLogin starts SP-initiated SSO: it remembers the AuthnRequest ID
// under the RelayState and redirects to Okta (HTTP-Redirect binding).
func (s *Server) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	req, err := s.saml.NewAuthnRequest()
	if err == nil {
		err = s.store.CreateSAMLRequest(r.Context(), hashString(req.RelayState), store.SAMLAuthn,
			req.ID, time.Now().Add(samlRequestTTL))
	}
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not start sign-in.")
		return
	}
	http.Redirect(w, r, req.URL, http.StatusFound)
}

// handleSAMLACS receives Okta's signed response (HTTP-POST binding).
//
// This is a cross-site POST from Okta, so SameSite=Lax cookies aren't sent
// and can't bind the response to the browser. Instead the RelayState maps
// to the single-use AuthnRequest ID, and the response must carry that ID as
// InResponseTo. Unsolicited (IdP-initiated) and replayed responses fail here.
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := r.ParseForm(); err != nil {
		s.loginFailed(w, r, "saml", "", errors.New("unreadable form"))
		return
	}
	reqID, err := s.store.ConsumeSAMLRequest(r.Context(), hashString(r.PostForm.Get("RelayState")), store.SAMLAuthn)
	if err != nil {
		s.loginFailed(w, r, "saml", "", errors.New("unsolicited, expired or replayed SAML response"))
		return
	}
	id, err := s.saml.ParseResponse(r, reqID)
	if err != nil {
		s.loginFailed(w, r, "saml", "", err)
		return
	}

	subject := id.OktaID
	if subject == "" {
		subject = id.NameID
	}
	s.completeLogin(w, r, loginIdentity{
		Method: "saml", Subject: subject, UserName: id.NameID, Email: id.Email,
		GivenName: id.FirstName, FamilyName: id.LastName,
		DisplayName: strings.TrimSpace(id.FirstName + " " + id.LastName),
		Groups:      id.Groups, HasGroups: id.HasGroups,
		SAMLNameID: id.NameID, SAMLSessionIndex: id.SessionIndex,
	})
}

// samlLogoutURL builds a signed LogoutRequest for the session being ended,
// or returns "" if Single Logout isn't available.
func (s *Server) samlLogoutURL(r *http.Request, nameID, sessionIndex string) string {
	req, err := s.saml.NewLogoutRequest(nameID, sessionIndex)
	if err != nil {
		s.log.Error("saml logout request", "err", err)
		return ""
	}
	if req.URL == "" {
		return ""
	}
	if err := s.store.CreateSAMLRequest(r.Context(), hashString(req.RelayState), store.SAMLLogout,
		req.ID, time.Now().Add(samlRequestTTL)); err != nil {
		s.log.Error("store saml logout request", "err", err)
		return ""
	}
	return req.URL
}

// handleSAMLSLO receives Okta's LogoutResponse. The local session was
// already ended before we redirected to Okta, so this only verifies and
// audits the IdP's answer; the user lands on the home page either way.
func (s *Server) handleSAMLSLO(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Form.Get("SAMLRequest") != "" {
		// IdP-initiated logout (Okta telling us the user signed out
		// elsewhere) isn't implemented; see README hardening notes.
		http.Error(w, "IdP-initiated logout is not supported", http.StatusNotImplemented)
		return
	}
	reqID, err := s.store.ConsumeSAMLRequest(r.Context(), hashString(r.Form.Get("RelayState")), store.SAMLLogout)
	if err == nil {
		err = s.saml.ParseLogoutResponse(r, reqID)
	}
	outcome, detail := audit.Success, map[string]any{"method": "saml"}
	if err != nil {
		outcome, detail["reason"] = audit.Failure, err.Error()
	}
	s.audit.Record(r.Context(), r, audit.IdPLogout, "", "", outcome, detail)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
