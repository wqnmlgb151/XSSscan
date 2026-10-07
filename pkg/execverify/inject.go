package execverify

import (
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
)

// verifyRequest overrides the initial document request in Chrome. Keeping the
// target origin preserves relative scripts, cookies and browser CSP behavior.
func (v *Verifier) verifyRequest(ctx context.Context, target model.Target, paramName string, paramType model.ParamType, payload string) (*ExecutionResult, error) {
	req, err := buildVerificationRequest(ctx, target, paramName, paramType, payload)
	if err != nil {
		return nil, err
	}
	req.URL.Fragment = ""
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()
	var replayed atomic.Bool
	replayErrors := make(chan error, 1)
	setup := chromedp.ActionFunc(func(tabCtx context.Context) error {
		chromedp.ListenTarget(tabCtx, func(ev interface{}) {
			e, ok := ev.(*fetch.EventRequestPaused)
			if !ok {
				return
			}
			// Never block the CDP event dispatch goroutine waiting for CDP.
			go func() {
				continuation := fetch.ContinueRequest(e.RequestID)
				if sameNavigationURL(e.Request.URL, req.URL) && replayed.CompareAndSwap(false, true) {
					headers := make(http.Header)
					for k, value := range e.Request.Headers {
						headers.Set(k, fmt.Sprint(value))
					}
					for k, values := range req.Header {
						headers[k] = values
					}
					headers.Del("Content-Length")
					entries := make([]*fetch.HeaderEntry, 0, len(headers))
					for k, values := range headers {
						for _, value := range values {
							entries = append(entries, &fetch.HeaderEntry{Name: k, Value: value})
						}
					}
					continuation = continuation.WithMethod(req.Method).WithHeaders(entries)
					if len(body) > 0 {
						continuation = continuation.WithPostData(base64.StdEncoding.EncodeToString(body))
					}
				}
				if err := continuation.Do(tabCtx); err != nil {
					select {
					case replayErrors <- err:
					default:
					}
				}
			}()
		})
		return fetch.Enable().WithPatterns([]*fetch.RequestPattern{{ResourceType: network.ResourceTypeDocument}}).Do(tabCtx)
	})
	result, err := v.runBrowserCheck(ctx, req.URL.String(), &ExecutionResult{}, setup)
	select {
	case replayErr := <-replayErrors:
		return result, fmt.Errorf("replay request: %w", replayErr)
	default:
	}
	if err == nil && !replayed.Load() {
		return result, fmt.Errorf("verification request was not replayed")
	}
	return result, err
}

// buildVerificationRequest injects into a private copy of the original request.
func buildVerificationRequest(ctx context.Context, target model.Target, paramName string, paramType model.ParamType, payload string) (*http.Request, error) {
	target.Headers = request.CloneHeaders(target.Headers)
	target.Cookies = request.CloneCookies(target.Cookies)
	switch paramType {
	case model.ParamBody:
		target.Body = request.InjectBodyValue(target.Body, paramName, payload, target.Headers)
	case model.ParamHeader:
		if target.Headers == nil {
			target.Headers = make(map[string]string)
		}
		for key := range target.Headers {
			if strings.EqualFold(key, paramName) {
				delete(target.Headers, key)
			}
		}
		target.Headers[paramName] = payload
	case model.ParamCookie, "":
		// Cookies are replaced after ApplyHeaders, including a raw Cookie header.
	default:
		return nil, fmt.Errorf("unsupported verification parameter type %s", paramType)
	}
	req, err := http.NewRequestWithContext(ctx, target.HTTPMethod(), target.URL, strings.NewReader(target.Body))
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		req.Body = http.NoBody
	}
	request.ApplyHeaders(req, target, false)
	// Chrome's transport is separate from the scanner's proxy transport.
	// A proxy credential must never be replayed as an origin header.
	req.Header.Del("Proxy-Authorization")
	if paramType == model.ParamCookie {
		cookies := req.Cookies()
		req.Header.Del("Cookie")
		for _, cookie := range cookies {
			if cookie.Name != paramName {
				req.AddCookie(cookie)
			}
		}
		req.AddCookie(&http.Cookie{Name: paramName, Value: payload})
	}
	return req, nil
}

func sameNavigationURL(raw string, expected *url.URL) bool {
	actual, err := url.Parse(raw)
	if err != nil {
		return false
	}
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(actual.Scheme, expected.Scheme) && strings.EqualFold(actual.Hostname(), expected.Hostname()) &&
		port(actual) == port(expected) && actual.EscapedPath() == expected.EscapedPath() && actual.RawQuery == expected.RawQuery
}

// buildHTMLPOC builds a self-contained HTML page for displaying a payload.
func buildHTMLPOC(payload string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>XSS POC</title></head>
<body>
%s
</body>
</html>`, html.EscapeString(payload))
}
