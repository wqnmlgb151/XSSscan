package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/report"
	"github.com/xsscan/xsscan/pkg/scanner"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

func TestReflectedXSSInHTMLBody(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>Search results for: %s</body></html>`, query)
	}))
	defer server.Close()

	cfg := scanner.Config{
		Concurrency: 5, RateLimit: 100, RateBurst: 200,
		RequestTimeout: 10 * time.Second, MaxPayloads: 20,
	}
	engine := scanner.NewEngine(cfg, zap.NewNop(), nil)
	target := model.Target{URL: server.URL + "/search?q=test", Method: "GET"}
	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("Expected findings but got none")
	}
	for _, f := range result.Findings {
		t.Logf("Finding: %s | Confidence: %.2f | Payload: %s", f.Description, f.Confidence, f.Payload)
	}

	// Test JSON report
	r := report.NewReporter()
	data, err := r.Generate(report.FromScanResult(result, 0), report.FormatJSON)
	if err != nil {
		t.Fatalf("Report generation failed: %v", err)
	}
	if !strings.Contains(string(data), "reflected_xss") {
		t.Error("JSON report missing finding data")
	}
}

func TestReflectedXSSInAttribute(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div class="%s">Hello</div></body></html>`, name)
	}))
	defer server.Close()

	cfg := scanner.Config{
		Concurrency: 5, RateLimit: 100, RateBurst: 200,
		RequestTimeout: 10 * time.Second, MaxPayloads: 20,
	}
	engine := scanner.NewEngine(cfg, zap.NewNop(), nil)
	target := model.Target{URL: server.URL + "/page?name=test", Method: "GET"}
	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	t.Logf("Found %d issues", len(result.Findings))
}

func TestReflectedXSSInScriptTag(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callback := r.URL.Query().Get("callback")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><script>var cb = '%s';</script></body></html>`, callback)
	}))
	defer server.Close()

	cfg := scanner.Config{
		Concurrency: 5, RateLimit: 100, RateBurst: 200,
		RequestTimeout: 10 * time.Second, MaxPayloads: 20,
	}
	engine := scanner.NewEngine(cfg, zap.NewNop(), nil)
	target := model.Target{URL: server.URL + "/api?callback=test", Method: "GET"}
	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	t.Logf("Found %d issues", len(result.Findings))
}

func TestNoFalsePositiveOnSanitizedInput(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		safe := strings.ReplaceAll(input, "<", "&lt;")
		safe = strings.ReplaceAll(safe, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>%s</body></html>`, safe)
	}))
	defer server.Close()

	cfg := scanner.Config{
		Concurrency: 5, RateLimit: 100, RateBurst: 200,
		RequestTimeout: 10 * time.Second, MaxPayloads: 20,
	}
	engine := scanner.NewEngine(cfg, zap.NewNop(), nil)
	target := model.Target{URL: server.URL + "/page?input=test", Method: "GET"}
	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) > 0 {
		t.Errorf("False positive: %d findings on sanitized input (should be 0)", len(result.Findings))
	}
}

func TestPOSTBodyJSONParameter(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]string
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		json.Unmarshal(body[:n], &data)
		name := data["name"]
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>Hello %s</body></html>`, name)
	}))
	defer server.Close()

	cfg := scanner.Config{
		Concurrency: 5, RateLimit: 100, RateBurst: 200,
		RequestTimeout: 10 * time.Second, MaxPayloads: 10,
	}
	engine := scanner.NewEngine(cfg, zap.NewNop(), nil)
	target := model.Target{
		URL:     server.URL + "/api",
		Method:  "POST",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"name":"test","email":"test@example.com"}`,
	}
	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	t.Logf("POST JSON: Found %d issues", len(result.Findings))
	for _, f := range result.Findings {
		t.Logf("  Finding: %s | Param: %s | Contexts: %v", f.Description, f.Parameter, f.Contexts)
	}
}

func TestPOSTBodyFormParameter(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		search := r.FormValue("search")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>Results: %s</body></html>`, search)
	}))
	defer server.Close()

	cfg := scanner.Config{
		Concurrency: 5, RateLimit: 100, RateBurst: 200,
		RequestTimeout: 10 * time.Second, MaxPayloads: 10,
	}
	engine := scanner.NewEngine(cfg, zap.NewNop(), nil)
	target := model.Target{
		URL:     server.URL + "/search",
		Method:  "POST",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    `search=test&page=1`,
	}
	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	t.Logf("POST Form: Found %d issues", len(result.Findings))
}

func TestConcurrentScanning(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>%s</body></html>`, query)
	}))
	defer server.Close()

	cfg := scanner.Config{
		Concurrency: 10, RateLimit: 1000, RateBurst: 2000,
		RequestTimeout: 10 * time.Second, MaxPayloads: 5,
	}
	engine := scanner.NewEngine(cfg, zap.NewNop(), nil)
	target := model.Target{URL: server.URL + "/search?q=test", Method: "GET"}
	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	t.Logf("Concurrent: %d findings from %d requests", len(result.Findings), result.Stats.PayloadsSent)
}

func TestReportGeneration(t *testing.T) {
	result := &model.ScanResult{
		Target: "http://example.com",
		Findings: []model.Finding{
			{
				ID: "XSS-001", Type: model.ReflectedXSS, Severity: model.High,
				Confidence: 0.85, URL: "http://example.com/search?q=x",
				Parameter: "q", Payload: `<script>alert(1)</script>`,
				Contexts: []string{"html_body"}, Description: "Reflected XSS in parameter 'q'",
			},
		},
		Stats: model.ScanStats{Duration: 1500, ParametersFound: 3, PayloadsSent: 45},
	}

	r := report.NewReporter()
	scanData := report.FromScanResult(result, 1500)

	jsonData, err := r.Generate(scanData, report.FormatJSON)
	if err != nil {
		t.Fatalf("JSON report failed: %v", err)
	}
	if !strings.Contains(string(jsonData), "reflected_xss") {
		t.Error("JSON report missing finding data")
	}

	mdData, err := r.Generate(scanData, report.FormatMarkdown)
	if err != nil {
		t.Fatalf("Markdown report failed: %v", err)
	}
	if !strings.Contains(string(mdData), "XSS") {
		t.Error("Markdown report missing title")
	}

	htmlData, err := r.Generate(scanData, report.FormatHTML)
	if err != nil {
		t.Fatalf("HTML report failed: %v", err)
	}
	if !strings.Contains(string(htmlData), "<html>") {
		t.Error("HTML report missing html tag")
	}
}
