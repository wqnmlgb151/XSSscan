package browser

import "context"

type fullVerificationWindowKey struct{}

func WithFullVerificationWindow(ctx context.Context, full bool) context.Context {
	return context.WithValue(ctx, fullVerificationWindowKey{}, full)
}

func FullVerificationWindow(ctx context.Context) bool {
	full, _ := ctx.Value(fullVerificationWindowKey{}).(bool)
	return full
}
