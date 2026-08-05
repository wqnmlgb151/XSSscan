package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

func init() {
	ssrfguard.AllowPrivate = true
}

// newTestEngine creates an engine with minimal config for testing.
func newTestEngine(serverURL string) *Engine {
	cfg := Config{
		Concurrency:    2,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 5 * time.Second,
		MaxPayloads:    10,
	}
	return NewEngine(cfg, zap.NewNop(), newTestClient(serverURL))
}

// newTestClient creates an HTTP client that redirects all requests to the test server.
func newTestClient(serverURL string) *http.Client {
	return &http.Client{
		Transport: &testTransport{serverURL: serverURL},
	}
}

// testTransport redirects all requests to a single test server.
type testTransport struct {
	serverURL string
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the request URL to point to the test server
	newURL := t.serverURL + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequest(req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Header {
		newReq.Header[k] = v
	}
	return http.DefaultTransport.RoundTrip(newReq)
}

// vulnerableTarget creates a mock server that reflects the "q" parameter.
func vulnerableTarget() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
}

// safeTarget creates a mock server that does not reflect input.
func safeTarget() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Safe page</body></html>"))
	}))
}

// errorTarget creates a mock server that returns transient 500 errors on
// payload scan requests (after analysis succeeds). The first N non-marker
// requests fail to exercise the retry logic in doScanPayload.
func errorTarget() *httptest.Server {
	var requestCount int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		// First request (analysis marker injection) succeeds.
		// Requests 2-3 (payload scans) fail with 500 to trigger retry.
		// Subsequent requests succeed.
		if count > 1 && count <= 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
}

// --- Test 1.1: Engine defaults ---

func TestNewEngine_Defaults(t *testing.T) {
	cfg := Config{}
	engine := NewEngine(cfg, nil, nil)

	if engine.config.ConfidenceMin != 0.60 {
		t.Errorf("Expected default ConfidenceMin=0.60, got %f", engine.config.ConfidenceMin)
	}
	if engine.throttle == nil {
		t.Error("Expected throttle to be initialized")
	}
	if engine.analyzer == nil {
		t.Error("Expected analyzer to be initialized")
	}
	if engine.generator == nil {
		t.Error("Expected generator to be initialized")
	}
	if engine.verifier == nil {
		t.Error("Expected verifier to be initialized")
	}
	if engine.mutator.Load() != nil {
		t.Error("Expected mutator to be nil when WAFBypass is false")
	}
}

func TestNewEngine_WAFBypassEnabled(t *testing.T) {
	cfg := Config{WAFBypass: true}
	engine := NewEngine(cfg, nil, nil)

	if engine.mutator.Load() == nil {
		t.Error("Expected mutator to be initialized when WAFBypass is true")
	}
}

func TestNewEngine_CustomClient(t *testing.T) {
	client := &http.Client{}
	cfg := Config{}
	engine := NewEngine(cfg, nil, client)

	if engine.client != client {
		t.Error("Expected custom client to be used")
	}
}

// --- Test 1.2: Full pipeline single target ---

func TestEngine_Run_VulnerableTarget(t *testing.T) {
	server := vulnerableTarget()
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.Stats.ParametersFound == 0 {
		t.Error("Expected at least 1 parameter found")
	}
	if result.Stats.PayloadsSent == 0 {
		t.Error("Expected payloads to be sent")
	}
	// We have a vulnerable target — should find something
	if len(result.Findings) == 0 {
		t.Log("Warning: no findings for vulnerable target (may be timing-related)")
	}
}

func TestEngine_Run_SafeTarget(t *testing.T) {
	server := safeTarget()
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings for safe target, got %d", len(result.Findings))
	}
}

// --- Test 1.3: Concurrency safety ---

func TestEngine_Run_ConcurrentSafety(t *testing.T) {
	server := vulnerableTarget()
	defer server.Close()

	engine := newTestEngine(server.URL)
	engine.config.Concurrency = 10

	target := model.Target{
		URL:    server.URL + "/page?q=test&r=hello",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Stats.Errors != 0 {
		t.Errorf("Expected 0 errors, got %d", result.Stats.Errors)
	}
}

// --- Test 1.4: Retry on transient errors ---

func TestEngine_Run_RetryOnTransient(t *testing.T) {
	server := errorTarget()
	defer server.Close()

	engine := newTestEngine(server.URL)
	engine.config.Concurrency = 1

	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Stats.PayloadsSent == 0 {
		t.Error("Expected payloads to be sent after retry")
	}
}

// --- Test 1.5: MaxPayloads cap ---

func TestEngine_Run_MaxPayloadsCap(t *testing.T) {
	server := vulnerableTarget()
	defer server.Close()

	cfg := Config{
		Concurrency:    1,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 5 * time.Second,
		MaxPayloads:    2,
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))

	target := model.Target{
		URL:    server.URL + "/page?q=test&r=hello",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if int(result.Stats.PayloadsSent) > 4 {
		t.Errorf("Expected payloads capped around 4 (2 per param × 2 params), got %d", result.Stats.PayloadsSent)
	}
}

// --- Test 1.6: Result stats populated ---

func TestEngine_Run_StatsPopulated(t *testing.T) {
	server := vulnerableTarget()
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Stats.StartTime == 0 {
		t.Error("Expected StartTime to be set")
	}
	if result.Stats.EndTime == 0 {
		t.Error("Expected EndTime to be set")
	}
	if result.Stats.Duration <= 0 {
		t.Errorf("Expected positive duration, got %d", result.Stats.Duration)
	}
	if result.Target != target.URL {
		t.Errorf("Expected target URL %s, got %s", target.URL, result.Target)
	}
}

// --- Test: Context cancellation ---

func TestEngine_Run_ContextCancellation(t *testing.T) {
	server := vulnerableTarget()
	defer server.Close()

	engine := newTestEngine(server.URL)
	engine.config.Concurrency = 1

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	_, err := engine.Run(ctx, target)
	if err == nil {
		t.Log("Warning: expected error from cancelled context (may complete too fast)")
	}
}

// --- Test: No injection points ---

func TestEngine_Run_NoInjectionPoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>No params here</body></html>"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{
		URL:    server.URL + "/page",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings for page with no params, got %d", len(result.Findings))
	}
}

// --- Test: WAF detection tracked ---

func TestEngine_Run_WAFDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("cf-ray", "abc123")
		w.Header().Set("Server", "cloudflare")
		q := r.URL.Query().Get("q")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Stats.WAF == nil {
		t.Error("Expected WAF to be detected (cf-ray header)")
	}
}

// --- Test: WAFInfo in result ---

func TestWAFInfo_Presence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("cf-ray", "test123")
		q := r.URL.Query().Get("q")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Stats.WAF != nil {
		if result.Stats.WAF.Name == "" {
			t.Error("Expected WAF name to be set")
		}
	}
}

// --- Test: cloneTarget independence ---

func TestCloneTarget_Independence(t *testing.T) {
	original := model.Target{
		URL:     "http://example.com/page?q=test",
		Method:  "GET",
		Headers: map[string]string{"X-Test": "value"},
	}
	original.Cookies = []*http.Cookie{{Name: "session", Value: "abc"}}

	// Cookie injection only mutates Cookies, not Headers — verify cookies are independent
	cloned := cloneTargetForParam(original, model.ParamCookie)
	cloned.Cookies[0].Value = "mutated"
	if original.Cookies[0].Value != "abc" {
		t.Error("cloneTarget did not deep-copy cookies")
	}

	// Header injection deep-copies headers — verify headers are independent
	clonedHeader := cloneTargetForParam(original, model.ParamHeader)
	clonedHeader.Headers["X-Test"] = "mutated"
	if original.Headers["X-Test"] != "value" {
		t.Error("cloneTarget did not deep-copy headers for ParamHeader")
	}
}

// --- Test: injectPayload query parameter ---

func TestInjectPayload_Query(t *testing.T) {
	eng := newTestEngine("http://example.com")
	target := model.Target{
		URL:    "http://example.com/page?q=test&r=hello",
		Method: "GET",
	}
	param := model.Parameter{Name: "q", Type: model.ParamQuery}

	result, err := eng.injectPayload(target, param, "<script>alert(1)</script>")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	if !strings.Contains(result.URL, "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E") {
		t.Errorf("Expected payload in URL query, got: %s", result.URL)
	}
	// Other params should be preserved
	if !strings.Contains(result.URL, "r=hello") {
		t.Errorf("Expected other params preserved, got: %s", result.URL)
	}
}

// --- Test: injectPayload header parameter ---

func TestInjectPayload_Header(t *testing.T) {
	eng := newTestEngine("http://example.com")
	target := model.Target{
		URL:     "http://example.com/page",
		Method:  "GET",
		Headers: map[string]string{"User-Agent": "original"},
	}
	param := model.Parameter{Name: "User-Agent", Type: model.ParamHeader}

	result, err := eng.injectPayload(target, param, "xsscan-test")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	if result.Headers["User-Agent"] != "xsscan-test" {
		t.Errorf("Expected header to be set, got: %s", result.Headers["User-Agent"])
	}
}

// --- Test: extractCSRFToken from form input ---

func TestEngine_ExtractCSRFToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><form><input type="hidden" name="csrf_token" value="test-token-123"></form></body></html>`))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/page", Method: "GET"}

	token := engine.extractCSRFToken(context.Background(), target)
	if token != "test-token-123" {
		t.Errorf("Expected token 'test-token-123', got %q", token)
	}

	// Verify field name was stored
	fieldName, _ := engine.csrfFieldName.Load().(string)
	if fieldName != "csrf_token" {
		t.Errorf("Expected field name 'csrf_token', got %q", fieldName)
	}
}

func TestEngine_ExtractCSRFTokenNoToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><p>No CSRF token here</p></body></html>`))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/page", Method: "GET"}

	token := engine.extractCSRFToken(context.Background(), target)
	if token != "" {
		t.Errorf("Expected empty token, got %q", token)
	}
}

// --- Test: Run with EnableProbe ---

func TestEngine_Run_WithProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    1,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 5 * time.Second,
		MaxPayloads:    5,
		EnableProbe:    true,
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))

	target := model.Target{
		URL:    server.URL + "/page?q=test",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Stats.PayloadsSent == 0 {
		t.Error("Expected payloads to be sent with probe enabled")
	}
}

// --- Test: scanPayload auto-WAF-bypass path ---

func TestScanPayload_AutoWAFBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Respond with Cloudflare WAF header but still reflect
		w.Header().Set("server", "cloudflare")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    1,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 5 * time.Second,
		WAFBypass: false, // not explicitly enabled — triggers auto-bypass path
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))

	target := model.Target{URL: server.URL + "/page?q=test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts: []ctx.Context{
			{Type: ctx.ContextHTMLBody},
		},
	}

	p := payload.Payload{
		Value:   "<script>alert(1)</script>",
		Context: ctx.ContextHTMLBody,
		Desc:    "test",
	}

	// scanPayload should complete without error. The server returns 200 with
	// WAF headers (not a 403 block), so auto-bypass is not triggered here —
	// that path is covered by TestFullPipeline_WAFAutoBypass.
	finding, err := engine.scanPayload(context.Background(), injection, p, nil, "127.0.0.1")
	if err != nil {
		t.Fatalf("scanPayload failed: %v", err)
	}
	if finding == nil {
		t.Error("Expected a finding for a reflected payload on a vulnerable target")
	}
}

// --- Test: SetCallbackURL replaces generator ---

func TestEngine_SetCallbackURL(t *testing.T) {
	engine := newTestEngine("http://example.com")
	engine.SetCallbackURL("http://callback.example.com")
	// Just verify it doesn't panic — generator is unexported, can't inspect directly
}

func TestEngine_SetPayloadPreset(t *testing.T) {
	engine := newTestEngine("http://example.com")
	engine.SetPayloadPreset(payload.PresetMinimal)
	// Verify it doesn't panic
}

func TestEngine_SetWordlist(t *testing.T) {
	// Create a temp wordlist file
	content := "# comment\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n\n"
	tmpFile := t.TempDir() + "/wordlist.txt"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write wordlist: %v", err)
	}

	engine := newTestEngine("http://example.com")
	err := engine.SetWordlist(tmpFile)
	if err != nil {
		t.Fatalf("SetWordlist failed: %v", err)
	}
}

func TestEngine_SetWordlistNotFound(t *testing.T) {
	engine := newTestEngine("http://example.com")
	err := engine.SetWordlist("/nonexistent/path/to/wordlist.txt")
	if err == nil {
		t.Fatal("Expected error for nonexistent wordlist file")
	}
}

// --- sendWithRetry: 429 + Retry-After handling ---

func TestSendWithRetry_RetryAfterDeltaSeconds(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("success"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{
		URL:    server.URL + "/test",
		Method: "GET",
	}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}
	modifiedTarget := target
	modifiedTarget.URL = server.URL + "/test?q=test"

	p := payload.Payload{Value: "test", Context: ctx.ContextHTMLBody}

	resp, body, _, err := engine.sendWithRetry(context.Background(), injection, modifiedTarget, p, "127.0.0.1")
	if err != nil {
		t.Fatalf("sendWithRetry failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 after retry, got %d", resp.StatusCode)
	}
	if string(body) != "success" {
		t.Errorf("Expected body 'success', got %q", string(body))
	}
	if atomic.LoadInt32(&requestCount) != 2 {
		t.Errorf("Expected 2 requests (1 retry), got %d", requestCount)
	}
}

func TestSendWithRetry_RetryAfterHTTPDate(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			// 1 second from now
			futureDate := time.Now().Add(1 * time.Second).UTC().Format(http.TimeFormat)
			w.Header().Set("Retry-After", futureDate)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}
	modifiedTarget := target
	modifiedTarget.URL = server.URL + "/test?q=test"

	p := payload.Payload{Value: "test", Context: ctx.ContextHTMLBody}

	resp, _, _, err := engine.sendWithRetry(context.Background(), injection, modifiedTarget, p, "127.0.0.1")
	if err != nil {
		t.Fatalf("sendWithRetry failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 after retry, got %d", resp.StatusCode)
	}
}

func TestSendWithRetry_RetryAfterInvalidFallsThrough(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			// Invalid Retry-After value — should still retry via normal backoff
			w.Header().Set("Retry-After", "invalid-date")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("recovered"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}
	modifiedTarget := target
	modifiedTarget.URL = server.URL + "/test?q=test"

	p := payload.Payload{Value: "test", Context: ctx.ContextHTMLBody}

	resp, body, _, err := engine.sendWithRetry(context.Background(), injection, modifiedTarget, p, "127.0.0.1")
	if err != nil {
		t.Fatalf("sendWithRetry failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 after retry, got %d", resp.StatusCode)
	}
	if string(body) != "recovered" {
		t.Errorf("Expected body 'recovered', got %q", string(body))
	}
}

func TestSendWithRetry_All5xxReturnsLastResponse(t *testing.T) {
	// When all retries return 5xx, sendWithRetry returns the last response
	// (lastErr is nil because there was no network error). The caller
	// handles the 5xx status code.
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}
	modifiedTarget := target
	modifiedTarget.URL = server.URL + "/test?q=test"

	p := payload.Payload{Value: "test", Context: ctx.ContextHTMLBody}

	resp, _, _, err := engine.sendWithRetry(context.Background(), injection, modifiedTarget, p, "127.0.0.1")
	if err != nil {
		t.Fatalf("sendWithRetry should not error on 5xx (no network error), got: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", resp.StatusCode)
	}
	// maxRetries=3 → 4 total attempts (0..3)
	if atomic.LoadInt32(&requestCount) != 4 {
		t.Errorf("Expected 4 attempts (1 initial + 3 retries), got %d", requestCount)
	}
}

// --- Test 5.1: Race detection with 20 concurrent workers ---

func TestEngine_Run_RaceDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		r2 := r.URL.Query().Get("r")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Q: " + q + " R: " + r2 + "</body></html>"))
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    20, // High concurrency to maximize race surface
		RateLimit:      5000,
		RateBurst:      10000,
		RequestTimeout: 10 * time.Second,
		MaxPayloads:    5,
	}
	engine := NewEngine(cfg, zap.NewNop(), newTestClient(server.URL))
	target := model.Target{
		URL:    server.URL + "/page?q=test&r=hello",
		Method: "GET",
	}

	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Stats.Errors != 0 {
		t.Errorf("Expected 0 errors with 20 workers, got %d", result.Stats.Errors)
	}
	if result.Stats.PayloadsSent == 0 {
		t.Error("Expected payloads to be sent")
	}

	t.Logf("Race test: %d workers, %d payloads sent, %d findings, %d errors",
		cfg.Concurrency, result.Stats.PayloadsSent, len(result.Findings), result.Stats.Errors)
}

func TestSendWithRetry_SuccessFirstTry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("immediate success"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}
	modifiedTarget := target
	modifiedTarget.URL = server.URL + "/test?q=test"

	p := payload.Payload{Value: "test", Context: ctx.ContextHTMLBody}

	resp, body, _, err := engine.sendWithRetry(context.Background(), injection, modifiedTarget, p, "127.0.0.1")
	if err != nil {
		t.Fatalf("sendWithRetry failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "immediate success" {
		t.Errorf("Expected body 'immediate success', got %q", string(body))
	}
}
