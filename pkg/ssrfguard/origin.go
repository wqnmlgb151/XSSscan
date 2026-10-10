package ssrfguard

import (
	"net/url"
	"strings"
)

// SameOrigin compares HTTP origins, including scheme and effective port.
// It deliberately does not use the broader login-domain rules in HostsMatch.
func SameOrigin(a, b string) bool {
	x, err := url.Parse(a)
	if err != nil {
		return false
	}
	y, err := url.Parse(b)
	if err != nil {
		return false
	}
	valid := func(u *url.URL) bool {
		return u.Hostname() != "" && u.User == nil && (u.Scheme == "http" || u.Scheme == "https")
	}
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return valid(x) && valid(y) && x.Scheme == y.Scheme && strings.EqualFold(x.Hostname(), y.Hostname()) && port(x) == port(y)
}
