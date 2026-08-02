// Package ssrfguard provides SSRF protection by validating target URLs
// against private/internal IP ranges before HTTP requests are made.
package ssrfguard

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// AllowPrivate flag enables scanning of private/internal networks.
// Set via --allow-private flag for authorized internal security testing.
var AllowPrivate = false

// IsURLTargetAllowed validates that a URL does not point to private,
// loopback, link-local, or other restricted IP ranges.
// Returns nil if the URL is safe to request, or an error describing the block.
func IsURLTargetAllowed(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}

	// Check literal IP addresses first (fast path)
	if ip := net.ParseIP(host); ip != nil {
		return checkIP(ip)
	}

	// Resolve hostname and check all resolved IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		// If resolution fails, block by default (fail closed)
		return fmt.Errorf("cannot resolve host %q: %w", host, err)
	}

	for _, ip := range ips {
		if err := checkIP(ip); err != nil {
			return err
		}
	}
	return nil
}

// checkIP validates a single IP against restricted ranges.
func checkIP(ip net.IP) error {
	if !AllowPrivate {
		if ip.IsLoopback() {
			return fmt.Errorf("blocked: loopback address %s", ip)
		}
		if ip.IsLinkLocalUnicast() {
			return fmt.Errorf("blocked: link-local address %s", ip)
		}
		if ip.IsLinkLocalMulticast() {
			return fmt.Errorf("blocked: link-local multicast %s", ip)
		}
		if isPrivateIP(ip) {
			return fmt.Errorf("blocked: private network address %s", ip)
		}
		// IPv4-mapped IPv6 addresses representing IPv4 loopback (::ffff:127.0.0.1)
		if ip.IsUnspecified() {
			return fmt.Errorf("blocked: unspecified address %s", ip)
		}
	}
	return nil
}

// isPrivateIP checks RFC1918 and RFC4193 private ranges.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"127.0.0.0/8",    // loopback (also caught by IsLoopback)
		"0.0.0.0/8",      // current network
		"169.254.0.0/16", // link-local (also caught by IsLinkLocalUnicast)
		"100.64.0.0/10",  // CGNAT (RFC6598)
		"fd00::/8",       // IPv6 unique local (RFC4193)
		"fe80::/10",      // IPv6 link-local
	}
	for _, cidr := range privateRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// HostsMatch checks whether two URLs share the same host or parent domain
// (case-insensitive). Used to validate that --login-url is legitimately
// related to --url.
//
// Matching rules:
// 1. Exact host match: app.target.com == app.target.com ✓
// 2. Parent domain match: auth.target.com vs app.target.com → share .target.com ✓
// 3. Different domains: target.com vs evil.com ✗
//
// This enables real-world auth setups where login is on a subdomain
// (auth.example.com, login.example.com, sso.example.com) while the
// target app lives on another subdomain (app.example.com, www.example.com).
func HostsMatch(urlA, urlB string) bool {
	a, err := url.Parse(urlA)
	if err != nil {
		return false
	}
	b, err := url.Parse(urlB)
	if err != nil {
		return false
	}
	hostA := strings.ToLower(a.Hostname())
	hostB := strings.ToLower(b.Hostname())
	if hostA == hostB {
		return true
	}
	// Check parent domain match: both must share the same registrable domain
	// e.g., auth.target.com and app.target.com share target.com
	parentA := parentDomain(hostA)
	parentB := parentDomain(hostB)
	if parentA == "" || parentB == "" {
		return false
	}
	return parentA == parentB
}

// parentDomain extracts the registrable domain (last two labels) from a host.
// Returns empty string for hosts with fewer than 2 labels (e.g., "localhost").
func parentDomain(host string) string {
	// Strip port if present
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	// Strip trailing dot (FQDN form)
	host = strings.TrimSuffix(host, ".")
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return ""
	}
	// For two-label hosts (e.g., example.com), return as-is.
	// For three-label hosts (e.g., auth.example.com), return last two labels.
	// For longer hosts, also return last two labels (handles co.uk-style TLDs
	// imperfectly, but this is an SSRF guard not a cookie domain validator).
	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}
