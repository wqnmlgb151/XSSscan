package ssrfguard

import "context"

type urlFilterKey struct{}

func WithURLFilter(ctx context.Context, filter func(string) error) context.Context {
	if filter == nil {
		return ctx
	}
	return context.WithValue(ctx, urlFilterKey{}, filter)
}
func InheritURLFilter(parent, caller context.Context) context.Context {
	if filter, ok := caller.Value(urlFilterKey{}).(func(string) error); ok {
		parent = WithURLFilter(parent, filter)
	}
	if filter, ok := caller.Value(navigationFilterKey{}).(func(string) error); ok {
		parent = WithNavigationFilter(parent, filter)
	}
	return parent
}

type navigationFilterKey struct{}

func WithNavigationFilter(ctx context.Context, filter func(string) error) context.Context {
	if filter == nil {
		return ctx
	}
	return context.WithValue(ctx, navigationFilterKey{}, filter)
}
func CheckNavigation(ctx context.Context, raw string) error {
	if filter, ok := ctx.Value(navigationFilterKey{}).(func(string) error); ok {
		return filter(raw)
	}
	return nil
}
