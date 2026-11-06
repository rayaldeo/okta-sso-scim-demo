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
- [ ] OIDC sign-in (auth code + PKCE) and RP-initiated logout
- [ ] SAML SP: metadata, ACS with signed-assertion validation, attribute mapping, Single Logout
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
- **Pure-Go SQLite** (`modernc.org/sqlite`), so no C toolchain is needed on Windows or in the container.

## License

MIT
