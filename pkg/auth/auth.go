// Package auth supports authenticated scanning with explicit success evidence.
package auth

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/pkg/csrf"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"golang.org/x/net/html"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const loginMaxBodySize = 1024 * 1024

type LoginConfig struct {
	LoginURL, Username, Password, UserField, PassField string
	Extra                                              map[string]string
	Headers                                            map[string]string
	SuccessContains, SuccessURL                        string
}

func Authenticate(client *http.Client, cfg LoginConfig) error {
	return AuthenticateContext(context.Background(), client, cfg)
}
func AuthenticateContext(ctx context.Context, client *http.Client, cfg LoginConfig) error {
	ctx, capture := httpclient.RecordContext(ctx)
	fail := func(message string, cause error) error {
		return &httpclient.ExchangeError{Message: message, Cause: cause, HTTP: capture.Snapshot()}
	}
	if err := ssrfguard.IsURLTargetAllowedContext(ctx, cfg.LoginURL); err != nil {
		return fail("login URL blocked", err)
	}
	client = httpclient.WithRedirectPolicy(httpclient.WithCapture(client))
	if cfg.UserField == "" {
		cfg.UserField = "username"
	}
	if cfg.PassField == "" {
		cfg.PassField = "password"
	}
	form := url.Values{}
	form.Set(cfg.UserField, cfg.Username)
	form.Set(cfg.PassField, cfg.Password)
	for key, value := range cfg.Extra {
		form.Set(key, value)
	}
	if len(cfg.Extra) == 0 {
		token, err := csrf.NewExtractor(client).ExtractCSRFContextWithHeaders(ctx, cfg.LoginURL, cfg.Headers)
		if ctx.Err() != nil {
			return fail("login canceled", ctx.Err())
		}
		if err == nil && token != nil {
			form.Set(token.FieldName, token.Value)
		}
	}
	u, _ := url.Parse(cfg.LoginURL)
	before := map[string]string{}
	if client.Jar != nil {
		for _, cookie := range client.Jar.Cookies(u) {
			before[cookie.Name] = cookie.Value
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.LoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fail("build login request", err)
	}
	for key, value := range cfg.Headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return fail("login request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, loginMaxBodySize+1))
	if err != nil {
		return fail("read login response", err)
	}
	if len(body) > loginMaxBodySize {
		return fail("login response exceeds analysis limit", nil)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fail(fmt.Sprintf("login returned HTTP %d", resp.StatusCode), nil)
	}
	if cfg.SuccessContains != "" && !strings.Contains(string(body), cfg.SuccessContains) {
		return fail("login success text was not found", nil)
	}
	if cfg.SuccessURL != "" && (resp.Request == nil || resp.Request.URL.String() != cfg.SuccessURL) {
		return fail("login success URL did not match", nil)
	}
	if cfg.SuccessContains != "" || cfg.SuccessURL != "" {
		return nil
	}
	lower := strings.ToLower(string(body))
	for _, indicator := range []string{"invalid password", "login failed", "incorrect", "authentication failed", "wrong password"} {
		if strings.Contains(lower, indicator) {
			return fail("login failed: "+indicator, nil)
		}
	}
	if containsPasswordInput(body) {
		return fail("login response still contains a password input", nil)
	}
	if client.Jar != nil {
		for _, cookie := range client.Jar.Cookies(u) {
			_, had := before[cookie.Name]
			if (!had || before[cookie.Name] != cookie.Value) && !strings.Contains(strings.ToLower(cookie.Name), "csrf") && cookie.Value != "" {
				return nil
			}
		}
	}
	return fail("login success unconfirmed: no new session cookie; configure login-success-contains or login-success-url", nil)
}
func containsPasswordInput(body []byte) bool {
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			return false
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if token.Data != "input" {
			continue
		}
		for _, attr := range token.Attr {
			if strings.EqualFold(attr.Key, "type") && strings.EqualFold(attr.Val, "password") {
				return true
			}
		}
	}
}
