package analyze

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

// TestAnalyzeReflectsMarkerInHTMLBody verifies the full pipeline detects an
// injection point when the server reflects the marker in an HTML body.
func TestAnalyzeReflectsMarkerInHTMLBody(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer server.Close()

	target := model.Target{URL: server.URL + "?q=test", Method: "GET"}
	analyzer := NewAnalyzer(server.Client())
	result, err := analyzer.Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.InjectionPoints) == 0 {
		t.Error("Expected at least one injection point for reflected marker in HTML body")
	}
	for _, ip := range result.InjectionPoints {
		if len(ip.Contexts) == 0 {
			t.Errorf("Expected contexts for injection point param %s", ip.Parameter.Name)
		}
	}
}

// TestAnalyzeJSONReflectionDetectsContext verifies that a JSON response with a
// reflected marker produces a ContextJSONValue context.
func TestAnalyzeJSONReflectionDetectsContext(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, `{"result":"%s"}`, q)
	}))
	defer server.Close()

	target := model.Target{URL: server.URL + "?q=test", Method: "GET"}
	analyzer := NewAnalyzer(server.Client())
	result, err := analyzer.Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.InjectionPoints) == 0 {
		t.Fatal("Expected injection point for JSON reflection")
	}

	foundJSONCtx := false
	for _, ip := range result.InjectionPoints {
		for _, c := range ip.Contexts {
			if c.Type == ctx.ContextJSONValue {
				foundJSONCtx = true
				if !c.Enclosed {
					t.Error("Expected Enclosed=true for JSON value context")
				}
				if c.QuoteChar != "\"" {
					t.Errorf("Expected QuoteChar='\"', got %q", c.QuoteChar)
				}
			}
		}
	}
	if !foundJSONCtx {
		t.Error("Expected at least one ContextJSONValue in injection point contexts")
	}
}

// TestAnalyzeNoMarkerNoInjectionPoints verifies that when the server does not
// reflect any marker, no injection points are produced.
func TestAnalyzeNoMarkerNoInjectionPoints(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>Hello Static World</body></html>")
	}))
	defer server.Close()

	target := model.Target{URL: server.URL + "?q=test", Method: "GET"}
	analyzer := NewAnalyzer(server.Client())
	result, err := analyzer.Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.InjectionPoints) != 0 {
		t.Errorf("Expected 0 injection points, got %d", len(result.InjectionPoints))
	}
}

// TestAnalyzePreservesAuthorizationHeader verifies that when a target has an
// Authorization header, it is preserved (not replaced with a marker) in the
// outgoing request.
func TestAnalyzePreservesAuthorizationHeader(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer server.Close()

	target := model.Target{
		URL:     server.URL + "?q=test",
		Method:  "GET",
		Headers: map[string]string{"Authorization": "Bearer secret-token-123"},
	}
	analyzer := NewAnalyzer(server.Client())
	_, err := analyzer.Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if receivedAuth != "Bearer secret-token-123" {
		t.Errorf("Expected Authorization header preserved, got %q", receivedAuth)
	}
}

// TestAnalyzeCSPHeaderParsed verifies that a CSP header set by the server is
// parsed and populated in the analysis result.
func TestAnalyzeCSPHeaderParsed(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer server.Close()

	target := model.Target{URL: server.URL + "?q=test", Method: "GET"}
	analyzer := NewAnalyzer(server.Client())
	result, err := analyzer.Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if result.CSP == nil {
		t.Fatal("Expected result.CSP to be populated")
	}
	if result.CSP.Raw == "" {
		t.Error("Expected CSP.Raw to contain the policy string")
	}
	if _, ok := result.CSP.Directives["default-src"]; !ok {
		t.Errorf("Expected default-src directive, got %v", result.CSP.Directives)
	}
}

// TestAnalyzeDetectsFramework verifies that HTML response body containing React
// markers results in framework detection in the analysis result.
func TestAnalyzeDetectsFramework(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, `<html><body><div id="react-root">%s</div></body></html>`, q)
	}))
	defer server.Close()

	target := model.Target{URL: server.URL + "?q=test", Method: "GET"}
	analyzer := NewAnalyzer(server.Client())
	result, err := analyzer.Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.Frameworks) == 0 {
		t.Fatal("Expected at least one framework detected")
	}
	found := false
	for _, fw := range result.Frameworks {
		if fw.Name == "React" {
			found = true
			if fw.Confidence <= 0 {
				t.Errorf("Expected positive confidence for React, got %f", fw.Confidence)
			}
		}
	}
	if !found {
		t.Errorf("Expected React framework in %+v", result.Frameworks)
	}
}

// TestAnalyzeMultipleParamsOnlyOneReflects verifies that when multiple query
// parameters exist but only one reflects in the response, only one injection
// point is reported.
func TestAnalyzeMultipleParamsOnlyOneReflects(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only reflect the "q" parameter; "r" is ignored.
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer server.Close()

	target := model.Target{URL: server.URL + "?q=test&r=hello", Method: "GET"}
	analyzer := NewAnalyzer(server.Client())
	result, err := analyzer.Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.InjectionPoints) != 1 {
		t.Errorf("Expected exactly 1 injection point (only q reflects), got %d", len(result.InjectionPoints))
	}
	if len(result.InjectionPoints) > 0 && result.InjectionPoints[0].Parameter.Name != "q" {
		t.Errorf("Expected injection point for param 'q', got %q", result.InjectionPoints[0].Parameter.Name)
	}
}

// TestAnalyzeEmptyParams verifies that a target with no extractable parameters
// returns an empty result without error.
func TestAnalyzeEmptyParams(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>ok</body></html>")
	}))
	defer server.Close()

	// No query params, no body.
	target := model.Target{URL: server.URL + "/", Method: "GET"}
	analyzer := NewAnalyzer(server.Client())
	result, err := analyzer.Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.InjectionPoints) != 0 {
		t.Errorf("Expected 0 injection points for param-less target, got %d", len(result.InjectionPoints))
	}
}
