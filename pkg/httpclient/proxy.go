// Package httpclient provides shared HTTP configuration for the xsscan project.
package httpclient

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

// ProxyConfig configures an HTTP proxy for all requests (e.g., Burp Suite, ZAP).
type ProxyConfig struct {
	URL      string // http://127.0.0.1:8080
	Username string // optional: basic auth username
	Password string // optional: basic auth password
	Insecure bool   // skip TLS verification for proxy HTTPS
}

// Validate checks the proxy URL format and SSRF safety.
// Port is fully user-controllable: specify any port in the URL (e.g., http://127.0.0.1:9090).
func (p *ProxyConfig) Validate() error {
	if p.URL == "" {
		return fmt.Errorf("proxy URL is empty")
	}

	proxyURL, err := url.Parse(p.URL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	// Only allow http, https, and socks5 schemes for proxy
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5" {
		return fmt.Errorf("proxy scheme must be http, https, or socks5 (got %q)", proxyURL.Scheme)
	}

	if proxyURL.Host == "" {
		return fmt.Errorf("proxy URL has no host")
	}

	// SSRF protection: don't allow proxying to internal IPs unless --allow-private
	if !ssrfguard.AllowPrivate {
		if err := ssrfguard.IsURLTargetAllowed(p.URL); err != nil {
			return fmt.Errorf("proxy target blocked by SSRF guard: %w", err)
		}
	}

	return nil
}

// ApplyToTransport configures the proxy on an HTTP transport.
func (p *ProxyConfig) ApplyToTransport(transport *http.Transport) error {
	proxyURL, err := url.Parse(p.URL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	transport.Proxy = http.ProxyURL(proxyURL)

	// Note: ProxyAuth is set per-request via header, not on Transport.
	// This is handled in ApplyHeaders if credentials are provided.

	return nil
}

// ProxyAuthHeader returns the Proxy-Authorization header value if credentials are set.
func (p *ProxyConfig) ProxyAuthHeader() (string, bool) {
	if p.Username != "" {
		return "Basic " + basicAuth(p.Username, p.Password), true
	}
	return "", false
}

// basicAuth creates a base64-encoded basic auth credential.
func basicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}
