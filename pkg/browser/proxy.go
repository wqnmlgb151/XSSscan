package browser

import (
	"context"
	"fmt"
	"net/url"
)

// ProxySettings is immutable configuration for one browser allocator.
// Credentials remain in memory and are never included in Chrome arguments.
type ProxySettings struct {
	server, username, password string
	direct                     bool
}
type proxyKey struct{}

func ParseProxy(raw, username, password string, direct bool) (ProxySettings, error) {
	settings := ProxySettings{direct: direct}
	if raw == "" {
		return settings, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return settings, fmt.Errorf("invalid browser proxy URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
		return settings, fmt.Errorf("unsupported browser proxy scheme")
	}
	settings.server = u.Scheme + "://" + u.Host
	if u.User != nil {
		settings.username = u.User.Username()
		settings.password, _ = u.User.Password()
	}
	if username != "" || password != "" {
		if username != "" {
			settings.username = username
		}
		settings.password = password
	}
	if u.Scheme == "socks5" && (settings.username != "" || settings.password != "") && !direct {
		return settings, fmt.Errorf("authenticated SOCKS5 is not supported by Chrome; use an HTTP proxy or explicit --browser-direct")
	}
	return settings, nil
}

func WithProxy(ctx context.Context, settings ProxySettings) context.Context {
	return context.WithValue(ctx, proxyKey{}, settings)
}
func ProxyFromContext(ctx context.Context) (ProxySettings, bool) {
	settings, ok := ctx.Value(proxyKey{}).(ProxySettings)
	return settings, ok
}

func (p ProxySettings) Server() string   { return p.server }
func (p ProxySettings) Username() string { return p.username }
func (p ProxySettings) Password() string { return p.password }
func (p ProxySettings) Direct() bool     { return p.direct }
func (p ProxySettings) String() string {
	if p.direct {
		return "direct"
	}
	return p.server
}
func (p ProxySettings) GoString() string { return p.String() }
