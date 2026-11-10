# Okta SSO + SCIM provisioning demo

A small Go web app that uses **Okta** as its identity provider:

- **SAML 2.0** single sign-on (the app is the service provider)
- **OpenID Connect** sign-in (authorization code flow with PKCE)
- **SCIM 2.0** provisioning server, so Okta pushes users and group memberships into the app
- **Group-based RBAC** (`admin` / `viewer`) enforced server-side
- **Audit log** of sign-ins, provisioning and deprovisioning

> Status: work in progress. See the roadmap below.

## Roadmap

- [x] App skeleton: config, SQLite store, server-side sessions, RBAC, audit log, tests, CI
- [x] OIDC sign-in (auth code + PKCE), JIT provisioning, RP-initiated logout ([Okta setup](docs/okta-setup.md))
- [x] SAML SP: SP-initiated SSO, signed-assertion validation, attribute mapping, signed Single Logout
- [ ] SCIM `/Users`: create, get, filter by `userName`, PUT, PATCH, deactivate
- [ ] SCIM `/Groups`: create, PATCH members, rename, delete
- [ ] Okta provisioning end-to-end + Okta SCIM spec tests
- [ ] Architecture and flow diagrams, screenshots, hardening notes
- [ ] Optional: deploy to Azure Container Apps

## Run locally

Requires the Go version in `go.mod` (1.27+).

```bash
cp .env.example .env        # then edit; .env is gitignored
go test ./...
go run ./cmd/server
```

Open http://localhost:8080.

## Design notes (so far)

- **Server-side sessions.** The cookie holds a random 256-bit token; the database stores only its SHA-256 hash. Sessions can be revoked instantly, and a database copy can't be replayed as cookies.
- **Roles are recomputed on every request** from group membership that SCIM keeps current, so removing someone from a group in Okta takes effect on their next click rather than at their next login.
- **Deactivation deletes sessions in the same transaction** as the `active=false` update.
- **Deny by default.** Users in neither mapped group can sign in but can't reach any protected page.
- **OIDC is the authorization code flow with PKCE (S256) plus a client secret.** `state` is bound to the browser by a short-lived cookie *and* to a single-use server-side row holding the nonce and PKCE verifier, so callbacks can't be forged, replayed or injected (login CSRF). The ID token's signature, issuer, audience, expiry and nonce are all verified.
- **Two provisioning modes.** `JIT_PROVISIONING=true`: the first sign-in creates the user and each sign-in refreshes groups from the token (a *missing* groups claim never strips roles). `false`: only SCIM can create users or change groups; a login token can't create or elevate an account.
- **Logout ends the Okta session too** (RP-initiated logout with `id_token_hint`), otherwise the next sign-in would succeed silently.
- **SAML responses are tied to a request we sent.** The ACS is a cross-site POST, so SameSite cookies can't bind it to the browser; instead the `RelayState` maps to a single-use AuthnRequest ID that must come back as `InResponseTo`. IdP-initiated (unsolicited) responses are refused, accepted assertion IDs are stored to block replay, and signatures, audience, destination and validity window are checked. SHA-1 signatures are rejected.
- **SAML vs OIDC in this app:** both end in the same account-matching and session code, so the comparison is only the protocol: XML assertions signed by Okta and POSTed through the browser, versus a JWT fetched server-to-server with a code and PKCE.
- **Pure-Go SQLite** (`modernc.org/sqlite`), so no C toolchain is needed on Windows or in the container.

## License

MIT
