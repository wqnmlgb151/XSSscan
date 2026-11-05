package ssrfguard

import (
	"context"
	"testing"
)

// Validate literal public addresses without network requests or external DNS.
func TestIsURLTargetAllowed_PublicLiteralIPs(t *testing.T) {

	for _, raw := range []string{"https://8.8.8.8/page?q=test", "http://1.1.1.1/", "https://[2606:4700:4700::1111]/"} {
		if err := (Policy{AllowPrivate: false}).IsURLTargetAllowedContext(context.Background(), raw); err != nil {
			t.Fatalf("public literal rejected: %s: %v", raw, err)
		}
	}
}

func TestIsURLTargetAllowed_LiteralPrivateIPs(t *testing.T) {

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
		if err := (Policy{AllowPrivate: false}).IsURLTargetAllowedContext(context.Background(), u); err == nil {
			t.Errorf("Private URL %q should be blocked", u)
		}
	}
}

func TestIsURLTargetAllowed_AllowPrivate(t *testing.T) {

	privateURLs := []string{
		"http://127.0.0.1/page",
		"http://10.0.0.1/admin",
		"http://192.168.1.1/router",
	}
	for _, u := range privateURLs {
		if err := (Policy{AllowPrivate: true}).IsURLTargetAllowedContext(context.Background(), u); err != nil {
			t.Errorf("With AllowPrivate=true, URL %q should be allowed, got: %v", u, err)
		}
	}
}

func TestIsURLTargetAllowed_InvalidURL(t *testing.T) {

	invalidURLs := []string{
		"",
		"not-a-url",
		"http://",
	}
	for _, u := range invalidURLs {
		if err := (Policy{AllowPrivate: false}).IsURLTargetAllowedContext(context.Background(), u); err == nil {
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
		{"http://sub.example.com/", "http://example.com/", true},    // share parent domain example.com
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

func TestHostsMatch_RegistrableDomainsAndIPs(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"https://victim.co.uk", "https://attacker.co.uk", false},
		{"https://auth.victim.co.uk", "https://app.victim.co.uk", true},
		{"https://alice.github.io", "https://bob.github.io", false},
		{"http://192.168.1.1", "http://10.0.1.1", false},
		{"http://192.168.1.1", "http://192.168.1.1:8080", true},
		{"http://[::1]", "http://[::2]", false},
		{"http://[::ffff:192.168.1.1]", "http://192.168.1.1", true},
		{"https://EXAMPLE.COM.", "https://example.com", true},
		{"", "", false},
		{"https://co.uk", "https://victim.co.uk", false},
	} {
		if got := HostsMatch(tc.a, tc.b); got != tc.want {
			t.Errorf("HostsMatch(%q, %q)=%v, want %v", tc.a, tc.b, got, tc.want)
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
