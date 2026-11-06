package config

import "testing"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := FromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL.String() != "http://localhost:8080" || c.SecureCookies() {
		t.Fatalf("unexpected base %v secure=%v", c.BaseURL, c.SecureCookies())
	}
	if c.OIDCEnabled() || c.SAMLEnabled() || c.SCIMEnabled() {
		t.Fatal("nothing should be enabled by default")
	}
}

func TestHTTPSEnablesSecureCookies(t *testing.T) {
	c, err := FromEnv(env(map[string]string{"BASE_URL": "https://demo.example.com/"}))
	if err != nil {
		t.Fatal(err)
	}
	if !c.SecureCookies() || c.BaseURL.Path != "" {
		t.Fatalf("secure=%v path=%q", c.SecureCookies(), c.BaseURL.Path)
	}
}

func TestRejectsBadInput(t *testing.T) {
	cases := map[string]map[string]string{
		"relative base url": {"BASE_URL": "localhost:8080"},
		"bad ttl":           {"SESSION_TTL": "forever"},
		"short scim token":  {"SCIM_BEARER_TOKEN": "too-short"},
		"same groups":       {"ROLE_ADMIN_GROUP": "x", "ROLE_VIEWER_GROUP": "x"},
	}
	for name, vars := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := FromEnv(env(vars)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
