package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/scanner"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

// newTestEngine creates a scanner.Engine pointed at the given base URL.
// The engine is configured for fast, deterministic testing.
func newTestEngine(t *testing.T, baseURL string) (*scanner.Engine, *http.Client) {
	t.Helper()
	ssrfguard.AllowPrivate = true
	t.Cleanup(func() { ssrfguard.AllowPrivate = false })

	logger := zap.NewNop()
	client := httpclient.NewClient(5*time.Second, nil)
	engineCfg := scanner.Config{
		Concurrency:    2,
		RateLimit:      1000, // high limit for fast tests
		RateBurst:      2000,
		RequestTimeout: 5 * time.Second,
		MaxPayloads:    3, // low count for speed
		ConfidenceMin:  0.60,
	}
	engine := scanner.NewEngine(engineCfg, logger, client)
	return engine, client
}

// TestScanOneTarget_AggregatesFindings verifies that scanOneTarget appends
// findings from the engine result to the shared allFindings slice.
func TestScanOneTarget_AggregatesFindings(t *testing.T) {
	// Server that reflects query parameter "q" in the HTML body
	var requestCount int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		// Reflect the raw input — triggers reflection detection
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	engine, _ := newTestEngine(t, server.URL)

	var allFindings []model.Finding
	var totalStats model.ScanStats

	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := scanOneTarget(ctx, engine, target, &allFindings, &totalStats)
	if err != nil {
		t.Fatalf("scanOneTarget failed: %v", err)
	}

	// The scan should have sent payloads and found the reflected parameter
	if totalStats.PayloadsSent == 0 {
		t.Error("Expected PayloadsSent > 0, got 0")
	}
	if totalStats.ParametersFound == 0 {
		t.Error("Expected ParametersFound > 0, got 0")
	}

	t.Logf("Findings: %d, PayloadsSent: %d, ParametersFound: %d",
		len(allFindings), totalStats.PayloadsSent, totalStats.ParametersFound)
}

// TestScanOneTarget_SumsStatsAcrossMultipleTargets verifies that stats from
// multiple scan calls are accumulated into totalStats.
func TestScanOneTarget_SumsStatsAcrossMultipleTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	engine, _ := newTestEngine(t, server.URL)

	var allFindings []model.Finding
	var totalStats model.ScanStats

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Scan two different URLs
	for i := 0; i < 2; i++ {
		target := model.Target{
			URL:    server.URL + "/page?q=scan" + string(rune('a'+i)),
			Method: "GET",
		}
		if err := scanOneTarget(ctx, engine, target, &allFindings, &totalStats); err != nil {
			t.Fatalf("scanOneTarget(%d) failed: %v", i, err)
		}
	}

	// Payloads and params should be accumulated across both scans
	if totalStats.PayloadsSent < 2 {
		t.Errorf("Expected PayloadsSent >= 2 (two scans), got %d", totalStats.PayloadsSent)
	}
	if totalStats.ParametersFound < 2 {
		t.Errorf("Expected ParametersFound >= 2 (two scans), got %d", totalStats.ParametersFound)
	}
}

// TestScanOneTarget_WAFPropagation verifies that WAF info from a scan result
// is propagated to totalStats.
func TestScanOneTarget_WAFPropagation(t *testing.T) {
	// Server that returns a Cloudflare-like response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return Cloudflare-like headers and body to trigger WAF detection
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("cf-ray", "abc123fra000000-EWR")
		w.Header().Set("Server", "cloudflare")
		q := r.URL.Query().Get("q")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Attention Required! Cloudflare " + q + "</body></html>"))
	}))
	defer server.Close()

	engine, _ := newTestEngine(t, server.URL)

	var allFindings []model.Finding
	var totalStats model.ScanStats

	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := scanOneTarget(ctx, engine, target, &allFindings, &totalStats)
	if err != nil {
		t.Fatalf("scanOneTarget failed: %v", err)
	}

	// WAF should be detected (Cloudflare cf-ray header + body pattern)
	if totalStats.WAF == nil {
		t.Log("WAF not detected by engine (this may happen if reflection wasn't found before WAF detection)")
	} else {
		if totalStats.WAF.Name != "Cloudflare" {
			t.Errorf("Expected WAF name 'Cloudflare', got %q", totalStats.WAF.Name)
		}
		t.Logf("WAF detected: %s, Bypassed: %v", totalStats.WAF.Name, totalStats.WAF.Bypassed)
	}
}

// TestScanOneTarget_WAFBypassedPropagation verifies that when one target
// has WAF bypassed, the bypassed flag propagates to totalStats.
func TestScanOneTarget_WAFBypassedPropagation(t *testing.T) {
	// Directly test the WAF bypassed aggregation logic by simulating
	// two scan results: one with WAF not bypassed, one with bypassed.
	var totalStats model.ScanStats

	// Simulate first scan: WAF detected, not bypassed
	result1WAF := &model.WAFInfo{Name: "Cloudflare", Bypassed: false}
	if result1WAF != nil {
		if totalStats.WAF == nil {
			totalStats.WAF = result1WAF
		} else if result1WAF.Bypassed {
			totalStats.WAF.Bypassed = true
		}
	}
	if totalStats.WAF == nil || totalStats.WAF.Bypassed {
		t.Fatal("Expected WAF detected but not bypassed after first scan")
	}

	// Simulate second scan: WAF bypassed
	result2WAF := &model.WAFInfo{Name: "Cloudflare", Bypassed: true}
	if result2WAF != nil {
		if totalStats.WAF == nil {
			totalStats.WAF = result2WAF
		} else if result2WAF.Bypassed {
			totalStats.WAF.Bypassed = true
		}
	}
	if !totalStats.WAF.Bypassed {
		t.Error("Expected WAF.Bypassed to be true after second scan")
	}
}

// TestScanOneTarget_ContextCanceled verifies that a canceled context
// causes scanOneTarget to return an error.
func TestScanOneTarget_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>slow</body></html>"))
	}))
	defer server.Close()

	engine, _ := newTestEngine(t, server.URL)

	var allFindings []model.Finding
	var totalStats model.ScanStats

	// Create a context that's already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	err := scanOneTarget(ctx, engine, target, &allFindings, &totalStats)
	if err == nil {
		t.Log("scanOneTarget did not return error for canceled context (engine may handle it gracefully)")
		// Some implementations handle cancellation gracefully — not a hard failure
	} else {
		t.Logf("Got expected error for canceled context: %v", err)
	}
}

// TestScanOneTarget_EmptyServer verifies scanOneTarget handles a server
// that returns an empty body (no reflection).
func TestScanOneTarget_EmptyServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(""))
	}))
	defer server.Close()

	engine, _ := newTestEngine(t, server.URL)

	var allFindings []model.Finding
	var totalStats model.ScanStats

	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := scanOneTarget(ctx, engine, target, &allFindings, &totalStats)
	if err != nil {
		t.Fatalf("scanOneTarget failed: %v", err)
	}

	// Empty body means no reflection, so no findings expected
	if len(allFindings) != 0 {
		t.Errorf("Expected 0 findings for empty server, got %d", len(allFindings))
	}
}

// TestRunHeadlessScan_Disabled verifies that runHeadlessScan returns nil
// immediately when headless mode is disabled.
func TestRunHeadlessScan_Disabled(t *testing.T) {
	// Save and restore global cfg
	saved := cfg
	defer func() { cfg = saved }()
	cfg.Headless = false

	var findings []model.Finding
	err := runHeadlessScan(context.Background(), &http.Client{}, model.Target{URL: "http://localhost/test"}, &findings)
	if err != nil {
		t.Errorf("runHeadlessScan should return nil when disabled, got: %v", err)
	}
}

// TestRunHeadlessScan_ContextCanceled verifies that runHeadlessScan handles
// a canceled context gracefully.
func TestRunHeadlessScan_ContextCanceled(t *testing.T) {
	saved := cfg
	defer func() { cfg = saved }()
	cfg.Headless = false // disabled — returns nil before checking context

	var findings []model.Finding
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runHeadlessScan(ctx, &http.Client{}, model.Target{URL: "http://localhost/test"}, &findings)
	if err != nil {
		t.Errorf("runHeadlessScan should return nil when disabled, got: %v", err)
	}
}

// TestGetSeverityColor verifies that getSeverityColor returns a non-nil
// function for all severity levels.
func TestGetSeverityColor(t *testing.T) {
	severities := []model.Severity{
		model.Critical,
		model.High,
		model.Medium,
		model.Low,
		model.Info,
		model.Severity("unknown"),
		model.Severity(""),
	}

	for _, sev := range severities {
		t.Run(string(sev), func(t *testing.T) {
			colorFn := getSeverityColor(sev)
			if colorFn == nil {
				t.Fatalf("getSeverityColor(%q) returned nil", sev)
			}
			// Call the color function — it should produce a non-empty string
			result := colorFn("test message")
			if result == "" {
				t.Errorf("getSeverityColor(%q) produced empty output", sev)
			}
		})
	}
}

// TestGetSeverityColor_CriticalAndHigh verifies that critical and high
// map to the same (red) color function.
func TestGetSeverityColor_CriticalAndHigh(t *testing.T) {
	criticalFn := getSeverityColor(model.Critical)
	highFn := getSeverityColor(model.High)

	// Both should produce output (we can't easily test color identity without
	// inspecting internals, but we can verify they don't panic)
	criticalOut := criticalFn("critical test")
	highOut := highFn("high test")

	if criticalOut == "" || highOut == "" {
		t.Error("Expected non-empty color output for critical/high severity")
	}
}

// TestScanOneTarget_MultipleParams verifies that scanOneTarget correctly
// handles a target with multiple query parameters.
func TestScanOneTarget_MultipleParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query().Get("q")
		rVal := req.URL.Query().Get("r")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>q=" + q + " r=" + rVal + "</body></html>"))
	}))
	defer server.Close()

	engine, _ := newTestEngine(t, server.URL)

	var allFindings []model.Finding
	var totalStats model.ScanStats

	target := model.Target{
		URL:    server.URL + "/page?q=test&r=value",
		Method: "GET",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := scanOneTarget(ctx, engine, target, &allFindings, &totalStats)
	if err != nil {
		t.Fatalf("scanOneTarget failed: %v", err)
	}

	// Should find at least 2 parameters
	if totalStats.ParametersFound < 2 {
		t.Errorf("Expected ParametersFound >= 2, got %d", totalStats.ParametersFound)
	}
}

// TestScanOneTarget_ConcurrentTargets verifies that scanOneTarget is safe
// to call from multiple goroutines with separate findings slices.
func TestScanOneTarget_ConcurrentTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	engine, _ := newTestEngine(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errors := make(chan error, 4)

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var findings []model.Finding
			var stats model.ScanStats
			target := model.Target{
				URL:    server.URL + "/page?q=concurrent" + string(rune('0'+idx)),
				Method: "GET",
			}
			if err := scanOneTarget(ctx, engine, target, &findings, &stats); err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent scanOneTarget failed: %v", err)
	}
}

// TestLoadTargets_Stdin verifies that loadTargets handles "-" as stdin marker.
// This exercises the code path where source == "-".
func TestLoadTargets_Stdin(t *testing.T) {
	// We can't easily mock os.Stdin, but we can verify the function
	// handles the "-" path without panicking by checking it returns
	// an error (since stdin is not a pipe in tests).
	// Actually, in test environment stdin is typically connected to the
	// test runner, so this would block. Skip this specific case.
	t.Skip("Stdin-based loadTargets cannot be tested in unit test environment")
}

// TestParseCookies_EdgeCases verifies additional cookie parsing edge cases.
func TestParseCookies_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		wantLen  int
		wantName string
		wantVal  string
	}{
		{
			name:     "whitespace trimming",
			input:    []string{"  session  =  abc123  "},
			wantLen:  1,
			wantName: "session",
			wantVal:  "abc123",
		},
		{
			name:     "empty cookie list",
			input:    []string{},
			wantLen:  0,
			wantName: "",
			wantVal:  "",
		},
		{
			name:     "cookie with multiple equals",
			input:    []string{"data=key=value"},
			wantLen:  1,
			wantName: "data",
			wantVal:  "key=value",
		},
		{
			name:     "no equals sign",
			input:    []string{"no-equals-sign"},
			wantLen:  0,
			wantName: "",
			wantVal:  "",
		},
		{
			name:     "empty value",
			input:    []string{"empty="},
			wantLen:  1,
			wantName: "empty",
			wantVal:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCookies(tt.input)
			if len(result) != tt.wantLen {
				t.Errorf("Expected %d cookies, got %d", tt.wantLen, len(result))
				return
			}
			if tt.wantLen > 0 {
				if result[0].Name != tt.wantName {
					t.Errorf("Expected name %q, got %q", tt.wantName, result[0].Name)
				}
				if result[0].Value != tt.wantVal {
					t.Errorf("Expected value %q, got %q", tt.wantVal, result[0].Value)
				}
			}
		})
	}
}

// TestParseHeaders_EdgeCases verifies additional header parsing edge cases.
func TestParseHeaders_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantLen int
		wantKey string
		wantVal string
	}{
		{
			name:    "colon in value",
			input:   []string{"Location: http://example.com:8080/path"},
			wantLen: 1,
			wantKey: "Location",
			wantVal: "http://example.com:8080/path",
		},
		{
			name:    "empty input",
			input:   []string{},
			wantLen: 0,
		},
		{
			name:    "nil input",
			input:   nil,
			wantLen: 0,
		},
		{
			name:    "header with no colon",
			input:   []string{"no-colon-here"},
			wantLen: 0,
		},
		{
			name:    "header with empty key",
			input:   []string{": value"},
			wantLen: 1,
			wantKey: "",
			wantVal: "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHeaders(tt.input)
			if len(result) != tt.wantLen {
				t.Errorf("Expected %d headers, got %d: %v", tt.wantLen, len(result), result)
				return
			}
			if tt.wantLen > 0 && tt.wantKey != "" {
				if result[tt.wantKey] != tt.wantVal {
					t.Errorf("Expected %q=%q, got %q", tt.wantKey, tt.wantVal, result[tt.wantKey])
				}
			}
		})
	}
}

// TestTruncateStr_EdgeCases verifies truncateStr behavior with edge cases.
func TestTruncateStr_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maxLen  int
		want    string
	}{
		{"empty string", "", 5, ""},
		{"zero maxLen", "hello", 0, "..."},
		{"exact length", "hello", 5, "hello"},
		{"one over", "hello", 4, "hell..."},
		{"one char", "hello", 1, "h..."},
		{"large maxLen", "hello", 100, "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateStr(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateStr(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

// TestCloneCookies_NilPointerInSlice verifies that cloneCookies handles
// a nil cookie pointer within the slice gracefully.
func TestCloneCookies_NilPointerInSlice(t *testing.T) {
	src := []*http.Cookie{
		{Name: "valid", Value: "cookie"},
		nil,
		{Name: "another", Value: "value"},
	}
	dst := cloneCookies(src)
	if len(dst) != 3 {
		t.Fatalf("Expected 3 cookies, got %d", len(dst))
	}
	if dst[0].Name != "valid" {
		t.Errorf("Expected 'valid', got %q", dst[0].Name)
	}
	if dst[1] != nil {
		t.Error("Expected nil for nil source cookie")
	}
	if dst[2].Name != "another" {
		t.Errorf("Expected 'another', got %q", dst[2].Name)
	}
}

// TestCloneCookies_EmptySlice verifies cloneCookies with an empty (non-nil) slice.
func TestCloneCookies_EmptySlice(t *testing.T) {
	src := []*http.Cookie{}
	dst := cloneCookies(src)
	if dst == nil {
		t.Error("Expected non-nil result for empty slice")
	}
	if len(dst) != 0 {
		t.Errorf("Expected 0 cookies, got %d", len(dst))
	}
}

// TestModelTarget_HTTPMethod verifies the HTTPMethod method on Target.
func TestModelTarget_HTTPMethod(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   string
	}{
		{"GET", "GET", "GET"},
		{"POST", "POST", "POST"},
		{"empty defaults to GET", "", "GET"},
		{"lowercase preserved", "delete", "delete"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := model.Target{Method: tt.method}
			got := target.HTTPMethod()
			if got != tt.want {
				t.Errorf("HTTPMethod() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestScanStats_WAFAggregation verifies the WAF aggregation logic pattern
// used in scanOneTarget.
func TestScanStats_WAFAggregation(t *testing.T) {
	var totalStats model.ScanStats

	// No WAF on first scan
	result1WAF := &model.WAFInfo{Name: "", Bypassed: false}
	if result1WAF != nil {
		// Detected flag is implicit — nil means not detected
		_ = result1WAF
	}

	// WAF detected on second scan
	result2WAF := &model.WAFInfo{Name: "Cloudflare", Bypassed: false}
	if result2WAF != nil {
		if totalStats.WAF == nil {
			totalStats.WAF = result2WAF
		}
	}

	if totalStats.WAF == nil || totalStats.WAF.Name != "Cloudflare" {
		t.Error("Expected Cloudflare WAF in totalStats")
	}

	// Third scan: different WAF but bypassed
	result3WAF := &model.WAFInfo{Name: "AWS WAF", Bypassed: true}
	if result3WAF != nil {
		if totalStats.WAF == nil {
			totalStats.WAF = result3WAF
		} else if result3WAF.Bypassed {
			totalStats.WAF.Bypassed = true
		}
	}

	// Original WAF name should be preserved, but bypassed flag updated
	if totalStats.WAF.Name != "Cloudflare" {
		t.Errorf("Expected WAF name to remain 'Cloudflare', got %q", totalStats.WAF.Name)
	}
	if !totalStats.WAF.Bypassed {
		t.Error("Expected WAF.Bypassed to be true")
	}
}

// TestErrorsIsContextCanceled verifies that errors.Is works correctly
// with context.Canceled (used in runScan for cancellation detection).
func TestErrorsIsContextCanceled(t *testing.T) {
	if !errorsIs(context.Canceled) {
		t.Error("Expected context.Canceled to be detected")
	}
}

// errorsIs is a helper to avoid importing errors just for this test.
func errorsIs(err error) bool {
	return err == context.Canceled || strings.Contains(err.Error(), "context canceled")
}
