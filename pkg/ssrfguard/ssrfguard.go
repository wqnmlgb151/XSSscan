// Package ssrfguard provides SSRF protection by validating target URLs
// against private/internal IP ranges before HTTP requests are made.
package ssrfguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// AllowPrivate flag enables scanning of private/internal networks.
// Deprecated: use explicit Policy/WithPolicy. The CLI no longer mutates this
// compatibility default; concurrent callers should never change it.
var AllowPrivate = false

// IsURLTargetAllowed validates that a URL does not point to private,
// loopback, link-local, or other restricted IP ranges.
// Returns nil if the URL is safe to request, or an error describing the block.
func IsURLTargetAllowed(rawURL string) error {
	return IsURLTargetAllowedContext(context.Background(), rawURL)
}

// IsURLTargetAllowedContext validates an HTTP destination with cancellable DNS.
func IsURLTargetAllowedContext(ctx context.Context, rawURL string) error {
	if filter, ok := ctx.Value(urlFilterKey{}).(func(string) error); ok {
		if err := filter(rawURL); err != nil {
			return err
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
		return fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}

	// Check literal IP addresses first (fast path)
	if ip := net.ParseIP(host); ip != nil {
		return PolicyFromContext(ctx).CheckIP(ip)
	}

	// Resolve hostname and check all resolved IPs
	ips, err := PolicyFromContext(ctx).resolve(ctx, host)
	if err != nil {
		// If resolution fails, block by default (fail closed)
		return fmt.Errorf("cannot resolve host %q: %w", host, err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("no addresses for %q", host)
	}
	for _, ip := range ips {
		if err := PolicyFromContext(ctx).CheckIP(ip.IP); err != nil {
			return err
		}
	}
	return nil
}

// checkIP validates a single IP against restricted ranges.
func checkIP(ip net.IP) error { return (Policy{AllowPrivate: AllowPrivate}).CheckIP(ip) }

func (p Policy) CheckIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}
	if !p.AllowPrivate {
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

// Prefixes are compiled once. Translation/tunnel ranges fail closed even when
// an embedded public IPv4 is present: their actual egress depends on local routing.
var restrictedPrefixes = func() []netip.Prefix {
	ranges := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/96", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "3fff::/20", "5f00::/16", "2001::/32", "2001:2::/48", "2001:db8::/32", "2001:10::/28", "2001:20::/28", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	}
	out := make([]netip.Prefix, 0, len(ranges))
	for _, raw := range ranges {
		out = append(out, netip.MustParsePrefix(raw))
	}
	return out
}()

func isPrivateIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	if embedded, ok := embeddedIPv4(address); ok && isPrivateIP(embedded.AsSlice()) {
		return true
	}
	for _, prefix := range restrictedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
var sixToFourPrefix = netip.MustParsePrefix("2002::/16")
var teredoPrefix = netip.MustParsePrefix("2001::/32")

func embeddedIPv4(address netip.Addr) (netip.Addr, bool) {
	if !address.Is6() {
		return netip.Addr{}, false
	}
	bytes := address.As16()
	switch {
	case nat64Prefix.Contains(address):
		return netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]}), true
	case sixToFourPrefix.Contains(address):
		return netip.AddrFrom4([4]byte{bytes[2], bytes[3], bytes[4], bytes[5]}), true
	case teredoPrefix.Contains(address):
		return netip.AddrFrom4([4]byte{^bytes[12], ^bytes[13], ^bytes[14], ^bytes[15]}), true
	}
	return netip.Addr{}, false
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
	hostA := strings.TrimSuffix(strings.ToLower(a.Hostname()), ".")
	hostB := strings.TrimSuffix(strings.ToLower(b.Hostname()), ".")
	if hostA == "" || hostB == "" {
		return false
	}
	ipA, ipB := net.ParseIP(hostA), net.ParseIP(hostB)
	if ipA != nil || ipB != nil {
		return ipA != nil && ipB != nil && ipA.Equal(ipB)
	}
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

// parentDomain uses the public suffix list, including private hosting suffixes,
// so independent co.uk or github.io tenants never share a trust boundary.
func parentDomain(host string) string {
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return domain
}
