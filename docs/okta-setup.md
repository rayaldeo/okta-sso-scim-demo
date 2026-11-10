# Okta setup

Step-by-step configuration of a free Okta Integrator account for this app.
Okta's Admin Console moves things around occasionally; if a label differs,
look for the nearest equivalent.

All URLs below assume `BASE_URL=http://localhost:8080`. If you change
`BASE_URL` (a tunnel or Azure), update every URL in Okta to match exactly.

## 0. Groups and users

1. **Directory → Groups → Add group**: create `app-admin` and `app-viewer`.
2. **Directory → People → Add person**: create two test users with mailboxes
   you control (Gmail `+` aliases work). Put one in each group.

## 1. OIDC app integration

1. **Applications → Applications → Create App Integration**
   - Sign-in method: **OIDC - OpenID Connect**
   - Application type: **Web Application** → **Next**
2. **New Web App Integration**
   - App integration name: `SSO SCIM Demo (OIDC)`
   - Grant type: **Authorization Code** only (leave Refresh Token unticked)
   - Sign-in redirect URIs: `http://localhost:8080/oidc/callback`
   - Sign-out redirect URIs: `http://localhost:8080/`
   - Assignments: **Limit access to selected groups** → `app-admin`, `app-viewer`
   - **Save**
3. **General** tab → **Client Credentials → Edit**
   - Client authentication: **Client secret**
   - Tick **Require PKCE as additional verification** → **Save**
   - Copy the **Client ID** and **Client secret** into `.env`
     (`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`).
4. **Sign On** tab → **OpenID Connect ID Token** → **Show legacy configuration**
   → **Group Claims → Edit**
   - Groups claim type: **Filter**
   - Groups claim filter: name `groups`, **Starts with** `app-`
   - **Save**. Without this, the ID token carries no `groups` claim and every
     user gets the `none` role. (Okta's newer "Token claims → Add expression"
     UI above it can do the same thing; the legacy filter is simpler.)

   Note: in the New Web App Integration form, choose **Use Okta-generated
   client ID** under *Client definition*, and clear Okta's default
   "My Web App" text from the name field.
5. Set `OIDC_ISSUER` in `.env` to your Okta org URL, e.g.
   `https://integrator-1234567.okta.com` (no trailing slash). This uses Okta's
   *org authorization server*, which is what the app-level groups claim
   filter in step 4 applies to.

### Check it

```bash
go run ./cmd/server
```

The startup log should include `"msg":"oidc ready"`. Open
http://localhost:8080/login, choose **Sign in with OIDC**, sign in as a test
user, and the dashboard should show your groups and role.

| Symptom | Likely cause |
|---|---|
| Okta page: "redirect_uri ... is not a valid redirect URI" | Sign-in redirect URI in Okta doesn't exactly match `BASE_URL/oidc/callback` |
| App page: "Okta did not sign you in: User is not assigned to the client application" | User isn't in `app-admin` or `app-viewer`, or the groups aren't assigned to the app |
| Signed in but role is `none` and Groups is empty | Groups claim filter (step 4) is missing or doesn't match the group names |
| Startup fails with `oidc discovery ... issuer did not match` | `OIDC_ISSUER` has a trailing slash or a typo |
| Sign out works but Okta shows an error page | Sign-out redirect URI isn't registered as `BASE_URL/` |

## 2. SAML app integration

First create the app's signing key and certificate (both gitignored):

```bash
go run ./cmd/gencert
```

1. **Applications → Applications → Create App Integration → SAML 2.0 → Next**
2. **General Settings**: App name `SSO SCIM Demo (SAML)` → **Next**
3. **Configure SAML**
   - Single sign-on URL: `http://localhost:8080/saml/acs`
     (keep **Use this for Recipient URL and Destination URL** ticked)
   - Audience URI (SP Entity ID): `http://localhost:8080/saml/metadata`
   - Default RelayState: leave empty
   - Name ID format: **EmailAddress**
   - Application username: **Okta username**
   - **Show Advanced Settings**:
     - Response: **Signed**; Assertion Signature: **Signed**
     - Signature Algorithm: **RSA-SHA256**; Digest Algorithm: **SHA256**
     - Assertion Encryption: **Unencrypted**
     - Signature Certificate: upload `certs/sp.crt` (Okta uses it to verify
       the app's signed logout requests). The two checkboxes below stay
       greyed out until a certificate is uploaded.
     - Enable Single Logout: tick **Allow application to initiate Single Logout**
       - Single Logout URL: `http://localhost:8080/saml/slo`
       - SP Issuer: `http://localhost:8080/saml/metadata`
     - Signed Requests: leave **unticked**. If ticked, Okta rejects the
       app's sign-in requests, which this app doesn't sign.
   - **Attribute Statements**: newer Okta versions no longer show these in
     the wizard. After **Finish**, open the **Sign On** tab → **Show legacy
     configuration** → **Profile attribute statements → Edit**:

     | Name | Format | Value |
     |---|---|---|
     | `email` | Unspecified | `user.email` |
     | `firstName` | Unspecified | `user.firstName` |
     | `lastName` | Unspecified | `user.lastName` |
     | `oktaId` | Unspecified | `user.getInternalProperty("id")` (optional) |

   - **Group attribute statements** (same legacy section): name `groups`,
     filter **Starts with** `app-`, then **Save**
   - In the wizard: **Next**, tick "This is an internal app that we have
     created", **Finish**
4. **Assignments** tab → **Assign → Assign to Groups**: `app-admin`, `app-viewer`
5. **Sign On** tab: copy the **Metadata URL** into `SAML_IDP_METADATA_URL` in `.env`
6. Optional, to skip MFA for the test users as with OIDC: **Security →
   Authentication Policies → App sign-in → (your password-only policy) → Applications → Add app**
   → `SSO SCIM Demo (SAML)`

### Check it

Restart the server; the log should include `"msg":"saml ready"`. Then, in a
private window, http://localhost:8080/login → **Sign in with SAML**. The
dashboard should show *Signed in with: saml*. **Sign out** should pass through
Okta (Single Logout) and land on the home page; the admin audit log shows
`logout` and `logout.idp_response` with outcome `success`.

| Symptom | Likely cause |
|---|---|
| Startup fails: `read SAML SP key` | Run `go run ./cmd/gencert` |
| Startup fails: `fetch SAML IdP metadata` | `SAML_IDP_METADATA_URL` is wrong; copy it from the Sign On tab |
| App: "Sign-in failed" and audit reason mentions `AudienceRestriction` | Audience URI in Okta isn't exactly `http://localhost:8080/saml/metadata` |
| Audit reason mentions `Destination` or `Recipient` | Single sign-on URL isn't exactly `http://localhost:8080/saml/acs` |
| Okta error page mentioning NameID policy | Name ID format isn't EmailAddress |
| Dashboard role is `none` | Group Attribute Statement missing or filter doesn't match `app-` |
| Sign out lands on an Okta error | Single Logout not enabled, wrong SLO URL, or `certs/sp.crt` not uploaded |
