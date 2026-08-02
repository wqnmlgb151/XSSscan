// Package auth provides authentication support for scanning authenticated endpoints.
package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/xsscan/xsscan/pkg/csrf"
)

// loginMaxBodySize limits how much of the login response we read for error detection.
const loginMaxBodySize = 4096

// LoginConfig defines parameters for form-based authentication.
type LoginConfig struct {
	LoginURL  string            // URL to POST credentials to
	Username  string            // Username value
	Password  string            // Password value
	UserField string            // Form field name for username (default "username")
	PassField string            // Form field name for password (default "password")
	Extra     map[string]string // Additional form fields (e.g., CSRF tokens)
}

// Authenticate performs a form-based login using the provided client.
// The client must have a cookie jar configured to retain the session.
// When no extra fields (e.g., CSRF tokens) are provided, it automatically
// attempts to extract a CSRF token from the login page.
func Authenticate(client *http.Client, cfg LoginConfig) error {
	if cfg.UserField == "" {
		cfg.UserField = "username"
	}
	if cfg.PassField == "" {
		cfg.PassField = "password"
	}

	form := url.Values{}
	form.Set(cfg.UserField, cfg.Username)
	form.Set(cfg.PassField, cfg.Password)
	for k, v := range cfg.Extra {
		form.Set(k, v)
	}

	// Auto-extract CSRF token if no extra fields provided and login URL given
	if len(cfg.Extra) == 0 && cfg.LoginURL != "" {
		extractor := csrf.NewExtractor(client)
		if token, err := extractor.ExtractCSRF(cfg.LoginURL); err == nil && token != nil {
			form.Set(token.FieldName, token.Value)
		}
	}

	resp, err := client.PostForm(cfg.LoginURL, form)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code — 4xx/5xx indicates failure
	if resp.StatusCode >= 400 {
		return fmt.Errorf("login returned HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, loginMaxBodySize))
	bodyLower := strings.ToLower(string(body))

	// Heuristic: if response contains login error indicators, login likely failed
	errorIndicators := []string{
		"invalid password", "login failed", "incorrect",
		"authentication failed", "wrong password",
	}
	for _, indicator := range errorIndicators {
		if strings.Contains(bodyLower, indicator) {
			return fmt.Errorf("login failed: server responded with error indicator: %s", indicator)
		}
	}

	// Verify a session cookie was actually established
	u, _ := url.Parse(cfg.LoginURL)
	if cookies := client.Jar.Cookies(u); len(cookies) > 0 {
		hasSession := false
		for _, c := range cookies {
			// Common session cookie names
			if strings.Contains(strings.ToLower(c.Name), "session") ||
				strings.Contains(strings.ToLower(c.Name), "sid") ||
				strings.Contains(strings.ToLower(c.Name), "token") ||
				strings.Contains(strings.ToLower(c.Name), "auth") {
				hasSession = true
				break
			}
		}
		if !hasSession {
			// Not a hard error — some apps use non-standard cookie names
			// but at least one cookie should be present
		}
	}

	return nil
}
