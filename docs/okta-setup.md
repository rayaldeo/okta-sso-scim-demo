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
