package ssrfguard

import (
	"context"
	"fmt"
	"net"
	"time"
)

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// DialContext resolves once, validates every result, and connects to a literal
// address from that result. The transport still uses the original host for TLS.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return dialResolved(ctx, network, address, net.DefaultResolver, dialer.DialContext)
}

func dialResolved(ctx context.Context, network, address string, resolver ipResolver, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %q", host)
	}
	for _, addr := range ips {
		if addr.Zone != "" {
			return nil, fmt.Errorf("scoped IP addresses are unsupported")
		}
		if err := checkIP(addr.IP); err != nil {
			return nil, err
		}
	}
	for _, addr := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var conn net.Conn
		conn, err = dial(ctx, network, net.JoinHostPort(addr.IP.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("connect %q: %w", address, err)
}
