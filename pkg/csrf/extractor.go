// Package csrf provides automatic CSRF token extraction from HTML pages.
// Used by the auth package to handle CSRF-protected login forms.
package csrf

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Common CSRF token field names found in HTML forms.
var csrfFieldNames = []string{
	"csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken",
	"_token", "authenticity_token", "xsrf", "_xsrf",
	"anti-csrf-token", "RequestVerificationToken",
	"__RequestVerificationToken", "csrfToken", "anti_csrf",
}

// Common CSRF meta tag names.
var csrfMetaNames = []string{
	"csrf-token", "csrf_token", "_csrf", "xsrf-token",
}

// fieldPattern matches any of the known CSRF field name patterns (case-insensitive).
var fieldPattern *regexp.Regexp

func init() {
	escaped := make([]string, len(csrfFieldNames))
	for i, name := range csrfFieldNames {
		escaped[i] = regexp.QuoteMeta(name)
	}
	// Matches name="csrf_token" name='csrf_token' name=`csrf_token`
	pattern := `(?i)(?:name=["'` + "`" + `](` + strings.Join(escaped, "|") + `)["'` + "`" + `])`
	fieldPattern = regexp.MustCompile(pattern)
}

// Token holds an extracted CSRF token and its field name.
type Token struct {
	Value     string
	FieldName string
	Source    string // "form", "meta", "header", "cookie"
}

// Extractor fetches pages and extracts CSRF tokens.
type Extractor struct {
	client *http.Client
}

// NewExtractor creates a new Extractor using the provided HTTP client.
func NewExtractor(client *http.Client) *Extractor {
	return &Extractor{client: client}
}

// ExtractCSRF fetches the given URL and attempts to find a CSRF token
// from form inputs, meta tags, response headers, or cookies.
// Returns the first non-empty token found, prioritizing form inputs.
func (e *Extractor) ExtractCSRF(pageURL string) (*Token, error) {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	resp, err := e.client.Get(pageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("page returned HTTP %d", resp.StatusCode)
	}

	// Read body (limit to 1MB to prevent memory issues)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 1. Try form input extraction (most common)
	if token := extractFromForm(body); token != nil {
		token.Source = "form"
		return token, nil
	}

	// 2. Try meta tag extraction
	if token := extractFromMeta(body); token != nil {
		token.Source = "meta"
		return token, nil
	}

	// 3. Try response headers
	if token := extractFromHeaders(resp.Header); token != nil {
		token.Source = "header"
		return token, nil
	}

	// 4. Try cookies (XSRF-TOKEN is common in Laravel/Angular)
	if token := extractFromCookies(e.client.Jar, u); token != nil {
		token.Source = "cookie"
		return token, nil
	}

	return nil, fmt.Errorf("no CSRF token found on page")
}

// extractFromForm parses HTML and looks for input fields with CSRF-like names.
func extractFromForm(body []byte) *Token {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}

	var traverse func(*html.Node) *Token
	traverse = func(n *html.Node) *Token {
		if n.Type == html.ElementNode {
			if n.Data == "input" {
				var name, value string
				for _, attr := range n.Attr {
					switch strings.ToLower(attr.Key) {
					case "name":
						name = attr.Val
					case "value":
						value = attr.Val
					}
				}
				if isCSRFFieldName(name) && value != "" {
					return &Token{Value: value, FieldName: name}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if result := traverse(c); result != nil {
				return result
			}
		}
		return nil
	}
	return traverse(doc)
}

// extractFromMeta looks for <meta name="csrf-token" content="..."> tags.
func extractFromMeta(body []byte) *Token {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}

	var traverse func(*html.Node) *Token
	traverse = func(n *html.Node) *Token {
		if n.Type == html.ElementNode && n.Data == "meta" {
			var name, content string
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "name":
					name = attr.Val
				case "content":
					content = attr.Val
				}
			}
			if isCSRFMetaName(name) && content != "" {
				return &Token{Value: content, FieldName: name}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if result := traverse(c); result != nil {
				return result
			}
		}
		return nil
	}
	return traverse(doc)
}

// extractFromHeaders checks for CSRF tokens in response headers.
func extractFromHeaders(headers http.Header) *Token {
	csrfHeaders := []string{"X-CSRF-Token", "X-XSRF-Token", "X-CSRFToken"}
	for _, h := range csrfHeaders {
		if v := headers.Get(h); v != "" {
			return &Token{Value: v, FieldName: h}
		}
	}
	return nil
}

// extractFromCookies checks for XSRF-TOKEN cookie (common pattern).
func extractFromCookies(jar http.CookieJar, u *url.URL) *Token {
	if jar == nil {
		return nil
	}
	cookies := jar.Cookies(u)
	for _, c := range cookies {
		if strings.Contains(strings.ToLower(c.Name), "xsrf") ||
			strings.Contains(strings.ToLower(c.Name), "csrf") {
			if c.Value != "" {
				return &Token{Value: c.Value, FieldName: c.Name}
			}
		}
	}
	return nil
}

// isCSRFFieldName checks if a field name matches known CSRF patterns.
func isCSRFFieldName(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range csrfFieldNames {
		pl := strings.ToLower(pattern)
		if lower == pl || strings.Contains(lower, pl) {
			return true
		}
	}
	return false
}

// isCSRFMetaName checks if a meta tag name matches known CSRF patterns.
func isCSRFMetaName(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range csrfMetaNames {
		if lower == pattern {
			return true
		}
	}
	return false
}
