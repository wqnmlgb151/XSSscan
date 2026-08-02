package ssrfguard

import (
	"testing"
)

func TestIsURLTargetAllowed_PublicHosts(t *testing.T) {
	AllowPrivate = false
	publicURLs := []string{
		"https://example.com/page?q=test",
		"http://google.com/search",
		"https://owasp.org/bugbounty",
	}
	for _, u := range publicURLs {
		if err := IsURLTargetAllowed(u); err != nil {
			// Note: in CI without network, DNS resolution may fail.
			// That's acceptable — fail-closed behavior.
			if err.Error() != "" && containsSubstring(err.Error(), "cannot resolve") {
				continue // expected in isolated environments
			}
			t.Errorf("Public URL %q should be allowed, got: %v", u, err)
		}
	}
}

func TestIsURLTargetAllowed_LiteralPrivateIPs(t *testing.T) {
	AllowPrivate = false
	privateURLs := []string{
		"http://127.0.0.1/page",
		"http://10.0.0.1/admin",
		"http://192.168.1.1/router",
		"http://172.16.0.1/internal",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/localhost",
		"http://[fd00::1]/private",
		"http://0.0.0.0/",
	}
	for _, u := range privateURLs {
		if err := IsURLTargetAllowed(u); err == nil {
			t.Errorf("Private URL %q should be blocked", u)
		}
	}
}

func TestIsURLTargetAllowed_AllowPrivate(t *testing.T) {
	AllowPrivate = true
	defer func() { AllowPrivate = false }()

	privateURLs := []string{
		"http://127.0.0.1/page",
		"http://10.0.0.1/admin",
		"http://192.168.1.1/router",
	}
	for _, u := range privateURLs {
		if err := IsURLTargetAllowed(u); err != nil {
			t.Errorf("With AllowPrivate=true, URL %q should be allowed, got: %v", u, err)
		}
	}
}

func TestIsURLTargetAllowed_InvalidURL(t *testing.T) {
	AllowPrivate = false
	invalidURLs := []string{
		"",
		"not-a-url",
		"http://",
	}
	for _, u := range invalidURLs {
		if err := IsURLTargetAllowed(u); err == nil {
			t.Errorf("Invalid URL %q should return error", u)
		}
	}
}

func TestHostsMatch_SameHost(t *testing.T) {
	pairs := []struct {
		a, b string
		want bool
	}{
		{"http://example.com/page", "http://example.com/login", true},
		{"http://example.com:80/page", "http://example.com:443/login", true},
		{"http://example.com/page", "http://other.com/page", false},
		{"http://sub.example.com/", "http://example.com/", true},  // share parent domain example.com
		{"http://auth.target.com/", "http://app.target.com/", true}, // share parent domain target.com
		{"http://evil.com/", "http://target.com/", false},           // different registrable domains
		{"http://EXAMPLE.com/", "http://example.com/", true},
		{"invalid", "http://example.com/", false},
	}
	for _, p := range pairs {
		got := HostsMatch(p.a, p.b)
		if got != p.want {
			t.Errorf("HostsMatch(%q, %q) = %v, want %v", p.a, p.b, got, p.want)
		}
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
