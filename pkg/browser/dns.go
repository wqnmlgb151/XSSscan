package browser

import "context"

type dnsRuleKey struct{}

func WithDNSRule(ctx context.Context, rule string) context.Context {
	return context.WithValue(ctx, dnsRuleKey{}, rule)
}

func DNSRuleFromContext(ctx context.Context) string {
	rule, _ := ctx.Value(dnsRuleKey{}).(string)
	return rule
}

func DNSPinEnabled(ctx context.Context) bool {
	_, ok := ctx.Value(dnsRuleKey{}).(string)
	return ok
}
