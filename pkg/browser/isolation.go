package browser

import "context"

type isolationKey struct{}
type legacyStartupKey struct{}

func WithSiteIsolationDisabled(ctx context.Context, disabled bool) context.Context {
	return context.WithValue(ctx, isolationKey{}, disabled)
}

func SiteIsolationDisabled(ctx context.Context) bool {
	disabled, _ := ctx.Value(isolationKey{}).(bool)
	return disabled || LegacyStartup(ctx)
}

func WithLegacyStartup(ctx context.Context, legacy bool) context.Context {
	return context.WithValue(ctx, legacyStartupKey{}, legacy)
}

func LegacyStartup(ctx context.Context) bool {
	legacy, _ := ctx.Value(legacyStartupKey{}).(bool)
	return legacy
}
