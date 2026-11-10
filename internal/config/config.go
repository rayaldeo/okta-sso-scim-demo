// Package config loads application settings from environment variables,
// optionally seeded from a local .env file (which is gitignored).
package config

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config holds all runtime settings. Secrets are only ever read from the
// environment; nothing here has a real default value for a secret.
type Config struct {
	ListenAddr string
	BaseURL    *url.URL
	DBPath     string
	SessionTTL time.Duration

	AdminGroup  string
	ViewerGroup string

	// JITProvisioning lets a first sign-in create the local user and set its
	// groups from the login token. Turn it off once SCIM is the only way
	// accounts get into the app.
	JITProvisioning bool

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCScopes       []string

	SAMLIdPMetadataURL string
	SAMLCertFile       string
	SAMLKeyFile        string

	SCIMBearerToken string
}

// MinSCIMTokenLen is the shortest bearer token we accept for the SCIM API.
const MinSCIMTokenLen = 32

// SecureCookies reports whether cookies should carry the Secure flag.
// True whenever the app is served over HTTPS.
func (c Config) SecureCookies() bool { return c.BaseURL.Scheme == "https" }

// OIDCEnabled reports whether OIDC login is configured.
func (c Config) OIDCEnabled() bool { return c.OIDCIssuer != "" && c.OIDCClientID != "" }

// SAMLEnabled reports whether SAML login is configured.
func (c Config) SAMLEnabled() bool { return c.SAMLIdPMetadataURL != "" }

// SCIMEnabled reports whether the SCIM API is configured.
func (c Config) SCIMEnabled() bool { return c.SCIMBearerToken != "" }

// Load reads .env (if present) and then the process environment.
func Load() (Config, error) {
	if err := loadDotEnv(".env"); err != nil {
		return Config{}, err
	}
	return FromEnv(os.Getenv)
}

// FromEnv builds a Config from a lookup function, which keeps it testable.
func FromEnv(get func(string) string) (Config, error) {
	or := func(key, def string) string {
		if v := strings.TrimSpace(get(key)); v != "" {
			return v
		}
		return def
	}

	base, err := url.Parse(or("BASE_URL", "http://localhost:8080"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return Config{}, fmt.Errorf("BASE_URL must be an absolute http(s) URL, got %q", get("BASE_URL"))
	}
	base.Path = strings.TrimSuffix(base.Path, "/")

	ttl, err := time.ParseDuration(or("SESSION_TTL", "8h"))
	if err != nil || ttl <= 0 {
		return Config{}, fmt.Errorf("SESSION_TTL must be a positive duration like 8h: %q", get("SESSION_TTL"))
	}

	jit, err := parseBool(or("JIT_PROVISIONING", "true"))
	if err != nil {
		return Config{}, fmt.Errorf("JIT_PROVISIONING: %w", err)
	}

	c := Config{
		JITProvisioning:    jit,
		OIDCScopes:         strings.Fields(or("OIDC_SCOPES", "openid profile email groups")),
		ListenAddr:         or("LISTEN_ADDR", ":8080"),
		BaseURL:            base,
		DBPath:             or("DB_PATH", "data/app.db"),
		SessionTTL:         ttl,
		AdminGroup:         or("ROLE_ADMIN_GROUP", "app-admin"),
		ViewerGroup:        or("ROLE_VIEWER_GROUP", "app-viewer"),
		OIDCIssuer:         strings.TrimSuffix(or("OIDC_ISSUER", ""), "/"),
		OIDCClientID:       or("OIDC_CLIENT_ID", ""),
		OIDCClientSecret:   or("OIDC_CLIENT_SECRET", ""),
		SAMLIdPMetadataURL: or("SAML_IDP_METADATA_URL", ""),
		SAMLCertFile:       or("SAML_SP_CERT_FILE", "certs/sp.crt"),
		SAMLKeyFile:        or("SAML_SP_KEY_FILE", "certs/sp.key"),
		SCIMBearerToken:    or("SCIM_BEARER_TOKEN", ""),
	}

	if c.SCIMBearerToken != "" && len(c.SCIMBearerToken) < MinSCIMTokenLen {
		return Config{}, fmt.Errorf("SCIM_BEARER_TOKEN must be at least %d characters", MinSCIMTokenLen)
	}
	if c.AdminGroup == c.ViewerGroup {
		return Config{}, errors.New("ROLE_ADMIN_GROUP and ROLE_VIEWER_GROUP must differ")
	}
	if c.OIDCEnabled() && !contains(c.OIDCScopes, "openid") {
		return Config{}, errors.New("OIDC_SCOPES must include openid")
	}
	return c, nil
}

// OIDCRedirectURL is the callback URL to register in Okta.
func (c Config) OIDCRedirectURL() string { return c.BaseURL.String() + "/oidc/callback" }

// PostLogoutRedirectURL is where Okta sends the browser after sign-out.
func (c Config) PostLogoutRedirectURL() string { return c.BaseURL.String() + "/" }

// SAML endpoints to register in Okta. The entity ID (SP issuer / audience)
// is the metadata URL, a common convention.
func (c Config) SAMLEntityID() string { return c.BaseURL.String() + "/saml/metadata" }
func (c Config) SAMLACSURL() string   { return c.BaseURL.String() + "/saml/acs" }
func (c Config) SAMLSLOURL() string   { return c.BaseURL.String() + "/saml/slo" }

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	}
	return false, fmt.Errorf("want true or false, got %q", s)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// loadDotEnv sets variables from a KEY=VALUE file without overriding
// anything already present in the environment. A missing file is fine.
func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected KEY=VALUE", path, n)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, val); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}
