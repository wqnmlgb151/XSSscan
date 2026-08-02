package scanner

import (
	"net/http"
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

// --- injectPayload: cookie isolation ---

func TestInjectPayload_CookieIsolation(t *testing.T) {
	original := model.Target{
		URL:     "http://example.com/page",
		Method:  "GET",
		Cookies: []*http.Cookie{{Name: "session", Value: "orig_session"}, {Name: "csrf", Value: "orig_csrf"}},
	}

	engine := &Engine{}
	param := model.Parameter{Name: "session", Type: model.ParamCookie}
	modified, err := engine.injectPayload(original, param, "PAYLOAD")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	// Modified should have the new value
	if modified.Cookies[0].Value != "PAYLOAD" {
		t.Errorf("Expected modified session=PAYLOAD, got %s", modified.Cookies[0].Value)
	}
	// Other cookie untouched
	if modified.Cookies[1].Value != "orig_csrf" {
		t.Errorf("Expected csrf=orig_csrf, got %s", modified.Cookies[1].Value)
	}
	// Original must be unchanged
	if original.Cookies[0].Value != "orig_session" {
		t.Errorf("Original session was mutated! Got %s", original.Cookies[0].Value)
	}
}

func TestInjectPayload_CookieAppendNew(t *testing.T) {
	original := model.Target{
		URL:     "http://example.com/page",
		Method:  "GET",
		Cookies: []*http.Cookie{{Name: "session", Value: "abc"}},
	}

	engine := &Engine{}
	param := model.Parameter{Name: "tracking", Type: model.ParamCookie}
	modified, err := engine.injectPayload(original, param, "PAYLOAD")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	if len(modified.Cookies) != 2 {
		t.Fatalf("Expected 2 cookies, got %d", len(modified.Cookies))
	}
	if modified.Cookies[1].Name != "tracking" || modified.Cookies[1].Value != "PAYLOAD" {
		t.Errorf("Expected tracking=PAYLOAD, got %s=%s", modified.Cookies[1].Name, modified.Cookies[1].Value)
	}
	// Original still has only 1 cookie
	if len(original.Cookies) != 1 {
		t.Errorf("Original cookies mutated: expected 1, got %d", len(original.Cookies))
	}
}

// --- injectPayload: query parameter ---

func TestInjectPayload_QueryParam(t *testing.T) {
	original := model.Target{
		URL:    "http://example.com/page?q=test&page=1",
		Method: "GET",
	}

	engine := &Engine{}
	param := model.Parameter{Name: "q", Type: model.ParamQuery}
	modified, err := engine.injectPayload(original, param, "PAYLOAD")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	if modified.URL == original.URL {
		t.Error("URL should have changed but didn't")
	}
	if !containsParam(modified.URL, "q=PAYLOAD") {
		t.Errorf("Expected q=PAYLOAD in URL, got: %s", modified.URL)
	}
	// page=1 should still be present
	if !containsParam(modified.URL, "page=1") {
		t.Errorf("Expected page=1 preserved, got: %s", modified.URL)
	}
}

func TestInjectPayload_QueryParamHPP(t *testing.T) {
	original := model.Target{
		URL:    "http://example.com/page?q=test",
		Method: "GET",
	}

	engine := &Engine{config: Config{TestHPP: true}}
	param := model.Parameter{Name: "q", Type: model.ParamQuery}
	modified, err := engine.injectPayload(original, param, "PAYLOAD")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	// HPP mode: should have both original and payload values
	qCount := countParamOccurrences(modified.URL, "q=")
	if qCount != 2 {
		t.Errorf("HPP: expected 2 q= params, got %d in URL: %s", qCount, modified.URL)
	}
}

// --- injectPayload: body parameter ---

func TestInjectPayload_BodyParam(t *testing.T) {
	original := model.Target{
		URL:    "http://example.com/api",
		Method: "POST",
		Body:   `{"name":"test","id":1}`,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	engine := &Engine{}
	param := model.Parameter{Name: "name", Type: model.ParamBody}
	modified, err := engine.injectPayload(original, param, "PAYLOAD")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	if modified.Body == original.Body {
		t.Error("Body should have changed but didn't")
	}
	// Original body must be unchanged
	if original.Body != `{"name":"test","id":1}` {
		t.Errorf("Original body was mutated: %s", original.Body)
	}
}

// --- injectPayload: path parameter ---

func TestInjectPayload_PathParam(t *testing.T) {
	original := model.Target{
		URL:    "http://example.com/users/123/profile",
		Method: "GET",
	}

	engine := &Engine{}
	param := model.Parameter{Name: "id", Value: "123", Type: model.ParamPath}
	modified, err := engine.injectPayload(original, param, "PAYLOAD")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	expected := "http://example.com/users/PAYLOAD/profile"
	if modified.URL != expected {
		t.Errorf("Expected %s, got %s", expected, modified.URL)
	}
	// Original unchanged
	if original.URL != "http://example.com/users/123/profile" {
		t.Errorf("Original URL was mutated: %s", original.URL)
	}
}

// --- injectPayload: unsupported type ---

func TestInjectPayload_UnsupportedType(t *testing.T) {
	original := model.Target{
		URL:    "http://example.com/page",
		Method: "GET",
	}

	engine := &Engine{}
	param := model.Parameter{Name: "x", Type: model.ParamType("invalid")}
	_, err := engine.injectPayload(original, param, "PAYLOAD")
	if err == nil {
		t.Error("Expected error for unsupported parameter type, got nil")
	}
}

// --- cloneTargetForParam: selective cloning ---

func TestCloneTargetForParam_QuerySharedHeaders(t *testing.T) {
	// Query injection intentionally shares the headers map (optimization).
	// The query code path never mutates headers, so this is safe.
	// This test documents that behavior — both point to the same map.
	headers := map[string]string{"X-Test": "original"}
	original := model.Target{
		URL:     "http://example.com/page",
		Headers: headers,
	}

	clone := cloneTargetForParam(original, model.ParamQuery)

	// For query type, headers map is shared — this is by design
	if clone.Headers["X-Test"] != "original" {
		t.Errorf("Expected shared header to be 'original', got %s", clone.Headers["X-Test"])
	}
	// URL is a value type (string), so it's always independent
	clone.URL = "http://modified.com"
	if original.URL != "http://example.com/page" {
		t.Errorf("URL should be independent (value type), but original was mutated")
	}
}

func TestCloneTargetForParam_HeaderDeepCopy(t *testing.T) {
	headers := map[string]string{"X-Test": "original"}
	original := model.Target{
		URL:     "http://example.com/page",
		Headers: headers,
	}

	clone := cloneTargetForParam(original, model.ParamHeader)

	// Mutate clone's headers — should NOT affect original
	clone.Headers["X-Test"] = "mutated"
	if original.Headers["X-Test"] != "original" {
		t.Errorf("Header clone leaked mutation to original: got %s", original.Headers["X-Test"])
	}
}

func TestCloneTargetForParam_CookieDeepCopy(t *testing.T) {
	original := model.Target{
		URL:     "http://example.com/page",
		Cookies: []*http.Cookie{{Name: "s", Value: "orig"}},
	}

	clone := cloneTargetForParam(original, model.ParamCookie)

	// Mutate clone's cookie value
	clone.Cookies[0].Value = "mutated"
	if original.Cookies[0].Value != "orig" {
		t.Errorf("Cookie clone leaked mutation to original: got %s", original.Cookies[0].Value)
	}
}

func TestCloneTargetForParam_BodyDeepCopyHeaders(t *testing.T) {
	headers := map[string]string{"Content-Type": "application/json"}
	original := model.Target{
		URL:     "http://example.com/api",
		Headers: headers,
	}

	clone := cloneTargetForParam(original, model.ParamBody)

	// Body injection clones headers (Content-Length may change)
	clone.Headers["Content-Length"] = "999"
	if original.Headers["Content-Length"] != "" {
		t.Errorf("Body clone leaked header mutation to original: got %s", original.Headers["Content-Length"])
	}
}

// --- helpers ---

func containsParam(url, param string) bool {
	return len(url) > 0 && containsSubstring(url, param)
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func countParamOccurrences(url, prefix string) int {
	count := 0
	for i := 0; i <= len(url)-len(prefix); i++ {
		if url[i:i+len(prefix)] == prefix {
			count++
		}
	}
	return count
}
