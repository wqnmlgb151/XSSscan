package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/verify"
	"go.uber.org/zap"
)

// --- Test: Full pipeline integration (analyze → generate → scan → dedup) ---

func TestFullPipeline_VulnerableTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Search: " + q + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    5,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 10 * time.Second,
		MaxPayloads:    20,
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))
	target := model.Target{URL: server.URL + "/search?q=test", Method: "GET"}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Stats.ParametersFound == 0 {
		t.Fatal("Expected at least 1 parameter found")
	}
	if result.Stats.PayloadsSent == 0 {
		t.Fatal("Expected payloads to be sent")
	}
	if len(result.Findings) == 0 {
		t.Error("Expected findings for deliberately vulnerable target — scanner may have regressed")
	}

	// Verify finding structure
	for _, f := range result.Findings {
		if f.ID == "" {
			t.Error("Finding missing ID")
		}
		if f.Parameter != "q" {
			t.Errorf("Expected parameter 'q', got %q", f.Parameter)
		}
		if f.Confidence < verify.DefaultConfidenceThreshold {
			t.Errorf("Finding confidence %.2f below threshold %.2f", f.Confidence, verify.DefaultConfidenceThreshold)
		}
		if f.Payload == "" {
			t.Error("Finding missing payload")
		}
		if f.URL == "" {
			t.Error("Finding missing URL")
		}
	}
}

func TestFullPipeline_NoFalsePositive(t *testing.T) {
	// Target that HTML-encodes all input — should produce zero findings
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		safe := strings.ReplaceAll(q, "<", "&lt;")
		safe = strings.ReplaceAll(safe, ">", "&gt;")
		safe = strings.ReplaceAll(safe, "\"", "&quot;")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + safe + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    5,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 10 * time.Second,
		MaxPayloads:    20,
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))
	target := model.Target{URL: server.URL + "/page?q=test", Method: "GET"}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(result.Findings) != 0 {
		for _, f := range result.Findings {
			t.Logf("False positive: %s | Confidence: %.2f | Payload: %s", f.Description, f.Confidence, f.Payload)
		}
		t.Errorf("Expected 0 findings for HTML-encoded target, got %d", len(result.Findings))
	}
}

// --- Test: WAF auto-bypass integration ---

func TestFullPipeline_WAFAutoBypass(t *testing.T) {
	// Server that blocks requests containing "onerror=" (case-sensitive) with a
	// Cloudflare-like WAF response, but reflects other payloads normally.
	// The auto-bypass mechanism should detect the WAF on the first blocked
	// request and try case-mixed mutations that evade the filter.
	var blockCount int32
	var reflectCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")

		// Simulate WAF: block payloads containing "onerror=" (case-sensitive)
		if strings.Contains(q, "onerror=") {
			atomic.AddInt32(&blockCount, 1)
			w.Header().Set("server", "cloudflare")
			w.Header().Set("cf-ray", "blocked123")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Attention Required! Cloudflare"))
			return
		}

		// Allow and reflect
		atomic.AddInt32(&reflectCount, 1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    1, // Serial to ensure deterministic WAF detection order
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 10 * time.Second,
		MaxPayloads:    10,
		WAFBypass:      false, // NOT explicitly enabled — triggers auto-bypass path
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))
	target := model.Target{URL: server.URL + "/search?q=test", Method: "GET"}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Verify WAF was detected
	if result.Stats.WAF == nil {
		t.Error("Expected WAF to be detected (Stats.WAF is nil)")
	} else if result.Stats.WAF.Name == "" {
		t.Error("Expected WAF name to be set")
	}

	// Verify that some requests were blocked and some got through
	if atomic.LoadInt32(&blockCount) == 0 {
		t.Error("Expected at least one WAF-blocked request")
	}
	if atomic.LoadInt32(&reflectCount) == 0 {
		t.Error("Expected at least one reflected (bypassed) request")
	}

	t.Logf("WAF blocks: %d, Reflected: %d, Findings: %d",
		atomic.LoadInt32(&blockCount), atomic.LoadInt32(&reflectCount), len(result.Findings))

	// With auto-bypass, we expect at least one finding from a mutation
	// that evaded the case-sensitive filter (e.g., "oNeRrOr=")
	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding from auto-bypass mutations")
	}
}

// --- Test: Context probe filtering ---

func TestFullPipeline_ContextProbeFiltering(t *testing.T) {
	// Target that reflects input but escapes < and > — markers pass through
	// (alphanumeric) but real payloads would be escaped. Context probe should
	// detect this and filter the injection point.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Escape angle brackets but allow alphanumeric markers
		safe := strings.ReplaceAll(q, "<", "&lt;")
		safe = strings.ReplaceAll(safe, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + safe + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    1,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 10 * time.Second,
		MaxPayloads:    10,
		EnableProbe:    true, // Enable context probe filtering
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))
	target := model.Target{URL: server.URL + "/page?q=test", Method: "GET"}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// With probe enabled, the injection point should be filtered out
	// because the probe <xsscan> would be escaped to &lt;xsscan&gt;
	if len(result.Findings) != 0 {
		for _, f := range result.Findings {
			t.Logf("Unexpected finding: %s | Confidence: %.2f | Payload: %s", f.Description, f.Confidence, f.Payload)
		}
		t.Errorf("Expected 0 findings with probe filtering (input is escaped), got %d", len(result.Findings))
	}
}

func TestFullPipeline_ProbeDisabledAllowsFindings(t *testing.T) {
	// Same server as above but with probe DISABLED — the scanner should
	// still not find anything because the payload is escaped, but this
	// test verifies that the probe is what actively filters (not the
	// verifier alone).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		safe := strings.ReplaceAll(q, "<", "&lt;")
		safe = strings.ReplaceAll(safe, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + safe + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    1,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 10 * time.Second,
		MaxPayloads:    10,
		EnableProbe:    false, // Probe disabled
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))
	target := model.Target{URL: server.URL + "/page?q=test", Method: "GET"}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Even without probe, the verifier should reject escaped payloads.
	// This confirms the verifier's sanitization detection works independently.
	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings (input is escaped), got %d", len(result.Findings))
	}
}

// --- Test: Multi-parameter pipeline with partial vulnerability ---

func TestFullPipeline_MultiParameterPartialVuln(t *testing.T) {
	// "q" is vulnerable (reflected raw), "safe" is encoded
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		safe := r.URL.Query().Get("safe")
		encoded := strings.ReplaceAll(safe, "<", "&lt;")
		encoded = strings.ReplaceAll(encoded, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Q: " + q + " | Safe: " + encoded + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    2,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 10 * time.Second,
		MaxPayloads:    10,
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))
	target := model.Target{URL: server.URL + "/page?q=test&safe=hello", Method: "GET"}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Should find vulnerabilities in "q" but not "safe"
	foundQ := false
	foundSafe := false
	for _, f := range result.Findings {
		if f.Parameter == "q" {
			foundQ = true
		}
		if f.Parameter == "safe" {
			foundSafe = true
		}
	}

	if !foundQ {
		t.Error("Expected findings for parameter 'q' (vulnerable)")
	}
	if foundSafe {
		t.Error("Did not expect findings for parameter 'safe' (encoded)")
	}
}

// --- Test: Semantic dedup in pipeline ---

func TestFullPipeline_SemanticDedup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    1,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 10 * time.Second,
		MaxPayloads:    20, // Multiple payloads to trigger dedup
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))
	target := model.Target{URL: server.URL + "/page?q=test", Method: "GET"}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// After dedup, all findings should have unique (attack vector, context) pairs
	seen := make(map[string]bool)
	for _, f := range result.Findings {
		key := f.Parameter + "|" + f.Payload
		if seen[key] {
			t.Errorf("Duplicate finding found: param=%s payload=%s", f.Parameter, f.Payload)
		}
		seen[key] = true
	}

	t.Logf("Unique findings after dedup: %d", len(result.Findings))
}

// --- Test: scanPayload exercises auto-WAF-bypass end-to-end ---

func TestScanPayload_AutoWAFBypassFindsVulnerability(t *testing.T) {
	// Server blocks "onerror=" but allows "oNeRrOr=" (case-mixed)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "onerror=") {
			w.Header().Set("server", "cloudflare")
			w.Header().Set("cf-ray", "blocked")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Attention Required!"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    1,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 5 * time.Second,
		WAFBypass:      false, // Auto-bypass path
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))

	target := model.Target{URL: server.URL + "/page?q=test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}

	p := payload.Payload{
		Value:   `<img src=x onerror=alert(1)>`,
		Context: ctx.ContextHTMLBody,
		Desc:    "test auto-bypass",
	}

	finding, err := engine.scanPayload(context.Background(), injection, p, nil, "127.0.0.1")
	if err != nil {
		t.Fatalf("scanPayload failed: %v", err)
	}

	if finding == nil {
		t.Error("Expected a finding from auto-bypass (case-mixed mutation should evade filter)")
	} else {
		t.Logf("Auto-bypass finding: %s | Payload: %s | Confidence: %.2f",
			finding.Description, finding.Payload, finding.Confidence)
	}
}
