package ssrfguard

import (
	"context"
	"net"
	"net/netip"
)

// Policy is immutable per-operation SSRF configuration. The package variable is
// consulted only by legacy calls without an explicit policy.
type Policy struct {
	AllowPrivate bool
	pinnedHost   string
	pinnedIPs    []netip.Addr
}

type policyKey struct{}

func WithPolicy(ctx context.Context, policy Policy) context.Context {
	return context.WithValue(ctx, policyKey{}, policy)
}

func PolicyFromContext(ctx context.Context) Policy {
	if policy, ok := ctx.Value(policyKey{}).(Policy); ok {
		return policy
	}
	return Policy{AllowPrivate: AllowPrivate}
}

func InheritPolicy(parent, caller context.Context) context.Context {
	if policy, ok := caller.Value(policyKey{}).(Policy); ok {
		return WithPolicy(parent, policy)
	}
	return parent
}

func (p Policy) IsURLTargetAllowedContext(ctx context.Context, raw string) error {
	return IsURLTargetAllowedContext(WithPolicy(ctx, p), raw)
}

func (p Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContext(WithPolicy(ctx, p), network, address)
}
