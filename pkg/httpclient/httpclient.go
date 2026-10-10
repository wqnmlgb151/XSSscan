// Package httpclient provides shared HTTP configuration for the xsscan project.
package httpclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"golang.org/x/net/publicsuffix"
)

// DefaultUA is sent when no User-Agent is specified by the caller.
const DefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// MaxResponseSize limits response body reading to prevent OOM from misbehaving servers.
const MaxResponseSize = 10 * 1024 * 1024 // 10MB

// NewClient creates an HTTP client with sensible defaults for scanning.
// Includes a cookie jar to maintain session state across requests.
// If proxy is non-nil, all requests are routed through the proxy.
func NewClient(timeout time.Duration, proxy *ProxyConfig) *http.Client {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{},
		DialContext:     ssrfguard.DialContext,
	}

	var proxyErr error
	if proxy != nil {
		proxyErr = proxy.ApplyToTransport(transport)
		if proxy.Insecure {
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}

	// Proxy selection runs for every request, including reused connections.
	// Validate the destination here as well as the actual direct/proxy dial IP.
	selectProxy := transport.Proxy
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		if proxyErr != nil {
			return nil, proxyErr
		}
		if err := ssrfguard.IsURLTargetAllowedContext(req.Context(), req.URL.String()); err != nil {
			return nil, err
		}
		if selectProxy != nil {
			return selectProxy(req)
		}
		return nil, nil
	}
	return &http.Client{
		Timeout:       timeout,
		Jar:           jar,
		Transport:     transport,
		CheckRedirect: CheckRedirect,
	}
}

// CheckRedirect confines automatic redirects to the original HTTP origin.
// Explicit authentication endpoints are independent requests, not redirects.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return http.ErrUseLastResponse
	}
	if len(via) > 0 && !ssrfguard.SameOrigin(via[0].URL.String(), req.URL.String()) {
		return fmt.Errorf("redirect blocked: cross-origin destination %s", req.URL.Redacted())
	}
	if err := ssrfguard.IsURLTargetAllowedContext(req.Context(), req.URL.String()); err != nil {
		return fmt.Errorf("redirect blocked: %w", err)
	}
	return nil
}

// WithRedirectPolicy retains the caller's transport, timeout, jar and redirect
// restrictions while enforcing scope. The supplied client is never mutated.
func WithRedirectPolicy(client *http.Client) *http.Client {
	return &http.Client{
		Transport: client.Transport,
		Timeout:   client.Timeout,
		Jar:       client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := CheckRedirect(req, via); err != nil {
				return err
			}
			if client.CheckRedirect != nil {
				return client.CheckRedirect(req, via)
			}
			return nil
		},
	}
}
