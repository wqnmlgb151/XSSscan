package analyze

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

func TestInjectPerParamMarkersHeaders(t *testing.T) {
	target := model.Target{
		URL:     "http://example.com/page?q=test",
		Method:  "GET",
		Headers: map[string]string{"X-Custom": "value1", "Referer": "http://google.com"},
		Cookies: []*http.Cookie{},
	}
	markers := map[string]string{
		"header:X-Custom": "MARKER_HEADER",
		"header:Referer":  "MARKER_REFERER",
	}
	modified := injectPerParamMarkers(target, markers, false)

	if modified.Headers["X-Custom"] != "MARKER_HEADER" {
		t.Errorf("Expected header X-Custom=MARKER_HEADER, got %s", modified.Headers["X-Custom"])
	}
	if modified.Headers["Referer"] != "MARKER_REFERER" {
		t.Errorf("Expected header Referer=MARKER_REFERER, got %s", modified.Headers["Referer"])
	}
}

func TestInjectPerParamMarkersCookies(t *testing.T) {
	target := model.Target{
		URL:    "http://example.com/page?q=test",
		Method: "GET",
		Cookies: []*http.Cookie{
			{Name: "session", Value: "abc123"},
			{Name: "csrf", Value: "xyz789"},
		},
	}
	markers := map[string]string{
		"cookie:csrf": "MARKER_CSRF",
	}
	modified := injectPerParamMarkers(target, markers, false)

	for _, c := range modified.Cookies {
		if c.Name == "csrf" && c.Value != "MARKER_CSRF" {
			t.Errorf("Expected cookie csrf=MARKER_CSRF, got %s", c.Value)
		}
		if c.Name == "session" && c.Value != "abc123" {
			t.Errorf("Expected session cookie unchanged, got %s", c.Value)
		}
	}
}

func TestInjectPerParamMarkersAllTypes(t *testing.T) {
	target := model.Target{
		URL:     "http://example.com/page?q=test&r=hello",
		Method:  "GET",
		Headers: map[string]string{"X-Custom": "value1"},
		Cookies: []*http.Cookie{{Name: "session", Value: "abc"}},
	}
	markers := map[string]string{
		"query:q":         "MARKER_Q",
		"query:r":         "MARKER_R",
		"header:X-Custom": "MARKER_H",
		"cookie:session":  "MARKER_C",
	}
	modified := injectPerParamMarkers(target, markers, false)

	// Query params should be replaced with unique markers
	if modified.URL == target.URL {
		t.Error("Expected URL query params to be replaced with markers")
	}
	// Headers should be replaced
	if modified.Headers["X-Custom"] != "MARKER_H" {
		t.Errorf("Expected header replaced, got %s", modified.Headers["X-Custom"])
	}
	// Cookies should be replaced
	if modified.Cookies[0].Value != "MARKER_C" {
		t.Errorf("Expected cookie replaced, got %s", modified.Cookies[0].Value)
	}
}

func TestInjectPerParamMarkersPreservesKeys(t *testing.T) {
	target := model.Target{
		URL:     "http://example.com/page?q=test",
		Method:  "GET",
		Headers: map[string]string{"X-Custom": "value1", "X-Real-IP": "1.2.3.4"},
	}
	markers := map[string]string{}
	modified := injectPerParamMarkers(target, markers, false)

	if len(modified.Headers) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(modified.Headers))
	}
	if _, ok := modified.Headers["X-Custom"]; !ok {
		t.Error("Expected X-Custom header to still exist")
	}
	if _, ok := modified.Headers["X-Real-IP"]; !ok {
		t.Error("Expected X-Real-IP header to still exist")
	}
}

func TestInjectPerParamMarkersPreserveAuth(t *testing.T) {
	target := model.Target{
		URL:     "http://example.com/page?q=test",
		Method:  "GET",
		Headers: map[string]string{"Authorization": "Bearer mytoken", "X-Custom": "value1"},
		Cookies: []*http.Cookie{{Name: "PHPSESSID", Value: "sess123"}, {Name: "tracking", Value: "track1"}},
	}
	markers := map[string]string{
		"header:Authorization": "MARKER_AUTH",
		"header:X-Custom":      "MARKER_CUSTOM",
		"cookie:PHPSESSID":     "MARKER_SESS",
		"cookie:tracking":      "MARKER_TRACK",
	}
	modified := injectPerParamMarkers(target, markers, true)

	// Authorization should be preserved
	if modified.Headers["Authorization"] != "Bearer mytoken" {
		t.Errorf("Expected Authorization header preserved, got %s", modified.Headers["Authorization"])
	}
	// X-Custom should be replaced
	if modified.Headers["X-Custom"] != "MARKER_CUSTOM" {
		t.Errorf("Expected X-Custom replaced, got %s", modified.Headers["X-Custom"])
	}
	// PHPSESSID should be preserved
	if modified.Cookies[0].Value != "sess123" {
		t.Errorf("Expected PHPSESSID preserved, got %s", modified.Cookies[0].Value)
	}
	// tracking cookie should be replaced
	if modified.Cookies[1].Value != "MARKER_TRACK" {
		t.Errorf("Expected tracking cookie replaced, got %s", modified.Cookies[1].Value)
	}
}

func TestGenerateMarkerUniqueness(t *testing.T) {
	// Verify generateMarker produces unique values
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		m := GenerateMarker()
		if seen[m] {
			t.Fatalf("Duplicate marker generated: %s", m)
		}
		seen[m] = true
		if len(m) != 18 { // "xsscan" (6) + 12 chars
			t.Errorf("Expected marker length 17, got %d: %s", len(m), m)
		}
		if m[:6] != "xsscan" {
			t.Errorf("Expected marker to start with 'xsscan', got %s", m)
		}
	}
}

func TestHasAuthCredentials(t *testing.T) {
	tests := []struct {
		name     string
		target   model.Target
		expected bool
	}{
		{
			"no auth",
			model.Target{Headers: map[string]string{"X-Custom": "val"}},
			false,
		},
		{
			"with Authorization",
			model.Target{Headers: map[string]string{"Authorization": "Bearer token"}},
			true,
		},
		{
			"with Cookie header",
			model.Target{Headers: map[string]string{"Cookie": "session=abc"}},
			true,
		},
		{
			"with session cookie",
			model.Target{Cookies: []*http.Cookie{{Name: "PHPSESSID", Value: "abc"}}},
			true,
		},
		{
			"with non-auth cookie only",
			model.Target{Cookies: []*http.Cookie{{Name: "tracking", Value: "xyz"}}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasAuthCredentials(tt.target); got != tt.expected {
				t.Errorf("hasAuthCredentials() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInjectPerParamMarkersUniquePerParam(t *testing.T) {
	target := model.Target{
		URL:     "http://example.com/page?a=1&b=2",
		Method:  "GET",
		Headers: map[string]string{"X-Test": "val"},
	}
	markers := map[string]string{
		"query:a":       "MARKER_A",
		"query:b":       "MARKER_B",
		"header:X-Test": "MARKER_H",
	}
	modified := injectPerParamMarkers(target, markers, false)

	u, err := url.Parse(modified.URL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}
	queryValues := u.Query()

	if queryValues.Get("a") != "MARKER_A" {
		t.Errorf("Expected a=MARKER_A, got %s", queryValues.Get("a"))
	}
	if queryValues.Get("b") != "MARKER_B" {
		t.Errorf("Expected b=MARKER_B, got %s", queryValues.Get("b"))
	}
	if modified.Headers["X-Test"] != "MARKER_H" {
		t.Errorf("Expected header=MARKER_H, got %s", modified.Headers["X-Test"])
	}
}

func TestParamKey(t *testing.T) {
	tests := []struct {
		param    model.Parameter
		expected string
	}{
		{model.Parameter{Name: "id", Type: model.ParamQuery}, "query:id"},
		{model.Parameter{Name: "id", Type: model.ParamBody}, "body:id"},
		{model.Parameter{Name: "User-Agent", Type: model.ParamHeader}, "header:User-Agent"},
		{model.Parameter{Name: "session", Type: model.ParamCookie}, "cookie:session"},
	}
	for _, tt := range tests {
		got := paramKey(tt.param)
		if got != tt.expected {
			t.Errorf("paramKey(%v) = %s, want %s", tt.param, got, tt.expected)
		}
	}
}
