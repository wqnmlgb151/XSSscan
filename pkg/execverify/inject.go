package execverify

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
)

// verifyViaProxy handles body/header/cookie parameters that can't be
// injected via URL navigation alone. It starts a local proxy server
// that forwards requests to the target with the payload injected,
// then navigates the browser to the proxy URL.
func (v *Verifier) verifyViaProxy(ctx context.Context, target model.Target, paramName string, paramType model.ParamType, payload string) (*ExecutionResult, error) {
	result := &ExecutionResult{}

	// Create a proxy handler that injects the payload
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Forward the request to the actual target with payload injected
		targetURL, err := url.Parse(target.URL)
			if err != nil {
				http.Error(w, fmt.Sprintf("parse target URL: %v", err), http.StatusInternalServerError)
				return
			}

		// Build the proxied request
		proxyReq, err := v.buildProxiedRequest(r, targetURL, paramName, paramType, payload, target)
		if err != nil {
			http.Error(w, fmt.Sprintf("proxy error: %v", err), http.StatusInternalServerError)
			return
		}

		// Execute the request
		client := &http.Client{
			Timeout: v.timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects
			},
		}
		resp, err := client.Do(proxyReq)
		if err != nil {
			http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for k, vals := range resp.Header {
			for _, val := range vals {
				w.Header().Add(k, val)
			}
		}
		w.WriteHeader(resp.StatusCode)

		// Read and forward the body
		buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			http.Error(w, fmt.Sprintf("read response body: %v", err), http.StatusBadGateway)
			return
		}
		w.Write(buf)
	})

	// Start the proxy server
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	// Navigate browser to the proxy URL
	return v.runBrowserCheck(ctx, proxyServer.URL, result)
}

// buildProxiedRequest creates an HTTP request to the target with the payload injected.
func (v *Verifier) buildProxiedRequest(r *http.Request, targetURL *url.URL, paramName string, paramType model.ParamType, payload string, target model.Target) (*http.Request, error) {
	// Build the target URL
	targetReqURL := targetURL.String()

	// Inject payload based on parameter type
	switch paramType {
	case model.ParamBody:
		// Inject into body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("read original request body: %w", err)
		}
		newBody := request.InjectBodyValue(string(body), paramName, payload, target.Headers)
		req, err := http.NewRequest(r.Method, targetReqURL, strings.NewReader(newBody))
		if err != nil {
			return nil, err
		}
		// Copy headers
		for k, vals := range r.Header {
			for _, v := range vals {
				req.Header.Add(k, v)
			}
		}
		return req, nil

	case model.ParamHeader:
		// Inject into header
		req, err := http.NewRequest(r.Method, targetReqURL, r.Body)
		if err != nil {
			return nil, err
		}
		for k, vals := range r.Header {
			for _, v := range vals {
				req.Header.Add(k, v)
			}
		}
		req.Header.Set(paramName, payload)
		return req, nil

	case model.ParamCookie:
		// Inject into cookie
		req, err := http.NewRequest(r.Method, targetReqURL, r.Body)
		if err != nil {
			return nil, err
		}
		for k, vals := range r.Header {
			for _, v := range vals {
				req.Header.Add(k, v)
			}
		}
		req.AddCookie(&http.Cookie{Name: paramName, Value: payload})
		return req, nil

	default:
		return nil, fmt.Errorf("unsupported parameter type for proxy: %s", paramType)
	}
}

// buildHTMLPOC builds a self-contained HTML page that injects the payload.
// Used for parameters that can't be easily proxied.
func buildHTMLPOC(payload string) string {
	// Escape the payload for safe embedding in HTML
	escaped := html.EscapeString(payload)
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>XSS POC</title></head>
<body>
%s
</body>
</html>`, escaped)
}

