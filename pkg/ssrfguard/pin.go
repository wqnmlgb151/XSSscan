package ssrfguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// PinURL validates one DNS answer set and returns an immutable policy snapshot
// and a Chrome resolver rule. Only that exact host is pinned; other hosts retain
// ordinary policy validation. Chrome redirects remain subject to origin guards.
func (p Policy) PinURL(ctx context.Context, raw string) (Policy, string, error) {
	return p.pinURL(ctx, raw, net.DefaultResolver)
}

func (p Policy) pinURL(ctx context.Context, raw string, resolver ipResolver) (Policy, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return p, "", fmt.Errorf("DNS pinning requires a valid HTTP(S) target")
	}
	host := strings.ToLower(u.Hostname())
	var answers []net.IPAddr
	literal := net.ParseIP(host)
	if literal != nil {
		answers = []net.IPAddr{{IP: literal}}
	} else {
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				return p, "", fmt.Errorf("DNS pinning requires an ASCII hostname")
			}
		}
		answers, err = resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return p, "", fmt.Errorf("resolve pinned host: %w", err)
		}
	}
	if len(answers) == 0 {
		return p, "", fmt.Errorf("DNS pinning received no addresses")
	}
	addresses := make([]netip.Addr, 0, len(answers))
	for _, answer := range answers {
		if answer.Zone != "" {
			return p, "", fmt.Errorf("scoped DNS pinning is unsupported")
		}
		if err := p.CheckIP(answer.IP); err != nil {
			return p, "", err
		}
		address, ok := netip.AddrFromSlice(answer.IP)
		if !ok {
			return p, "", fmt.Errorf("invalid DNS pinning address")
		}
		addresses = append(addresses, address.Unmap())
	}
	// Prefer a validated IPv4 answer when present (localhost commonly returns ::1 first).
	for i, address := range addresses {
		if address.Is4() {
			addresses[0], addresses[i] = addresses[i], addresses[0]
			break
		}
	}
	p.pinnedHost = host
	p.pinnedIPs = addresses
	if literal != nil {
		return p, "", nil
	}
	destination := addresses[0].String()
	if addresses[0].Is6() {
		destination = "[" + destination + "]"
	}
	return p, "MAP " + host + " " + destination, nil
}

func (p Policy) resolve(ctx context.Context, host string) ([]net.IPAddr, error) {
	if strings.EqualFold(host, p.pinnedHost) && len(p.pinnedIPs) > 0 {
		answers := make([]net.IPAddr, 0, len(p.pinnedIPs))
		for _, address := range p.pinnedIPs {
			answers = append(answers, net.IPAddr{IP: address.AsSlice()})
		}
		return answers, nil
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}
