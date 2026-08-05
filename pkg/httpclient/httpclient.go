// Package httpclient provides shared HTTP configuration for the xsscan project.
package httpclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

// DefaultUA is sent when no User-Agent is specified by the caller.
const DefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// MaxResponseSize limits response body reading to prevent OOM from misbehaving servers.
const MaxResponseSize = 10 * 1024 * 1024 // 10MB

// NewClient creates an HTTP client with sensible defaults for scanning.
// Includes a cookie jar to maintain session state across requests.
// If proxy is non-nil, all requests are routed through the proxy.
func NewClient(timeout time.Duration, proxy *ProxyConfig) *http.Client {
	jar, _ := cookiejar.New(&cookiejar.Options{})

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}

	if proxy != nil {
		proxy.ApplyToTransport(transport)
		if proxy.Insecure {
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}

	return &http.Client{
		Timeout: timeout,
		Jar:     jar,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if err := ssrfguard.IsURLTargetAllowed(req.URL.String()); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}
}
