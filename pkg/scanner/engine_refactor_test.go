package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"time"

	"github.com/xsscan/xsscan/pkg/execverify"
	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/pkg/verify"
	"go.uber.org/zap"
)

// --- Test: sendWithRetry success path ---

func TestSendWithRetry_SuccessOnFirstAttempt(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	var callCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		w.WriteHeader(200)
		w.Write([]byte("<html><body>test</body></html>"))
	}))
	defer srv.Close()

	engine := makeTestEngine()
	target := model.Target{URL: srv.URL + "/test", Method: "GET"}
	injection := makeTestInjection(target)

	resp, body, _, err := engine.sendWithRetry(context.Background(), injection, target, payload.Payload{}, "127.0.0.1")
	if err != nil {
		t.Fatalf("Expected success, got: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "test") {
		t.Errorf("Expected body to contain 'test', got: %s", string(body))
	}
	if n := atomic.LoadInt64(&callCount); n != 1 {
		t.Errorf("Expected 1 call, got %d", n)
	}
}

func TestSendWithRetry_RetriesOn500(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	var callCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&callCount, 1)
		if n < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer srv.Close()

	engine := makeTestEngine()
	engine.throttle = NewThrottle(1000, 2000, false)
	target := model.Target{URL: srv.URL + "/test", Method: "GET"}
	injection := makeTestInjection(target)

	resp, _, _, err := engine.sendWithRetry(context.Background(), injection, target, payload.Payload{}, "127.0.0.1")
	if err != nil {
		t.Fatalf("Expected success after retries, got: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
	if n := atomic.LoadInt64(&callCount); n != 3 {
		t.Errorf("Expected 3 calls (2 fail + 1 success), got %d", n)
	}
}

func TestSendWithRetry_503RetriesThenReturnsLastResponse(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	var callCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		w.WriteHeader(503)
	}))
	defer srv.Close()

	engine := makeTestEngine()
	engine.throttle = NewThrottle(1000, 2000, false)
	target := model.Target{URL: srv.URL + "/test", Method: "GET"}
	injection := makeTestInjection(target)

	resp, _, _, err := engine.sendWithRetry(context.Background(), injection, target, payload.Payload{}, "127.0.0.1")
	// 5xx doesn't produce an error — it returns the last response
	if err != nil {
		t.Fatalf("5xx should not produce error, got: %v", err)
	}
	if resp.StatusCode != 503 {
		t.Errorf("Expected 503, got %d", resp.StatusCode)
	}
	// Should have retried maxRetries+1 times
	if n := atomic.LoadInt64(&callCount); n != int64(maxRetries+1) {
		t.Errorf("Expected %d calls, got %d", maxRetries+1, n)
	}
}

// --- Test: buildFindingFromResponse ---

func TestBuildFindingFromResponse_VulnerableFinding(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	engine := makeTestEngine()
	target := model.Target{URL: "http://127.0.0.1/?q=test", Method: "GET"}
	injection := model.InjectionPoint{
		Target: target,
		Parameter: model.Parameter{
			Name: "q",
			Type: model.ParamQuery,
		},
		Contexts: []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}

	body := []byte(`<html><body><img src=x onerror=alert(1)></body></html>`)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	p := payload.Payload{
		Value:   `<img src=x onerror=alert(1)>`,
		Context: ctx.ContextHTMLBody,
	}

	finding, wafResult := engine.buildFindingFromResponse(resp, body, target, injection, p, nil)
	if finding == nil {
		t.Fatal("Expected finding, got nil — payload should be reflected in exploitable context")
	}
	if finding.Parameter != "q" {
		t.Errorf("Expected param 'q', got '%s'", finding.Parameter)
	}
	if finding.Payload != p.Value {
		t.Errorf("Expected payload '%s', got '%s'", p.Value, finding.Payload)
	}
	if wafResult.Detected {
		t.Error("Expected no WAF detected for test server")
	}
}

func TestBuildFindingFromResponse_NotVulnerable(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	engine := makeTestEngine()
	target := model.Target{URL: "http://127.0.0.1/test", Method: "GET"}
	injection := model.InjectionPoint{
		Target: target,
		Parameter: model.Parameter{
			Name: "q",
			Type: model.ParamQuery,
		},
		Contexts: []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}

	body := []byte(`<html><body>nothing here</body></html>`)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}
	p := payload.Payload{
		Value:   `<img src=x onerror=alert(1)>`,
		Context: ctx.ContextHTMLBody,
	}

	finding, _ := engine.buildFindingFromResponse(resp, body, target, injection, p, nil)
	if finding != nil {
		t.Error("Expected nil finding (payload not reflected), got finding")
	}
}

// --- Test: applyVerificationResult ---

func TestApplyVerificationResult_ExecutedDialog(t *testing.T) {
	engine := makeTestEngine()
	f := &model.Finding{
		Parameter:  "q",
		Confidence: 0.75,
	}

	result := &fakeExecResult{executed: true, dialogType: "alert", confidence: 0.95}
	engine.applyVerificationResult(f, result.toExecverifyResult())

	if !f.ExecutionVerified {
		t.Error("Expected ExecutionVerified=true")
	}
	if f.ExecutionConfidence != 0.95 {
		t.Errorf("Expected confidence 0.95, got %f", f.ExecutionConfidence)
	}
	// Confidence should be boosted by 0.15, capped at 1.0
	if f.Confidence != 0.90 {
		t.Errorf("Expected boosted confidence 0.90, got %f", f.Confidence)
	}
}

func TestApplyVerificationResult_DOMMutationOnly(t *testing.T) {
	engine := makeTestEngine()
	f := &model.Finding{
		Parameter:  "q",
		Confidence: 0.75,
	}

	result := &fakeExecResult{executed: false, confidence: 0.70, domMutations: []string{"img_injection"}}
	engine.applyVerificationResult(f, result.toExecverifyResult())

	if f.ExecutionVerified {
		t.Error("Expected ExecutionVerified=false for DOM mutation only")
	}
	if f.ExecutionConfidence != 0.70 {
		t.Errorf("Expected confidence 0.70, got %f", f.ExecutionConfidence)
	}
	// Confidence unchanged (not boosted, not downgraded)
	if f.Confidence != 0.75 {
		t.Errorf("Expected unchanged confidence 0.75, got %f", f.Confidence)
	}
}

func TestApplyVerificationResult_NotExecuted(t *testing.T) {
	engine := makeTestEngine()
	f := &model.Finding{
		Parameter:  "q",
		Confidence: 0.80,
	}

	result := &fakeExecResult{executed: false, confidence: 0}
	engine.applyVerificationResult(f, result.toExecverifyResult())

	if f.ExecutionVerified {
		t.Error("Expected ExecutionVerified=false")
	}
	// Confidence should be downgraded by 0.85 factor
	expected := 0.80 * 0.85
	if f.Confidence != expected {
		t.Errorf("Expected downgraded confidence %f, got %f", expected, f.Confidence)
	}
}

func TestApplyVerificationResult_ConfidenceCapAt1(t *testing.T) {
	engine := makeTestEngine()
	f := &model.Finding{
		Parameter:  "q",
		Confidence: 0.95,
	}

	result := &fakeExecResult{executed: true, dialogType: "alert", confidence: 0.99}
	engine.applyVerificationResult(f, result.toExecverifyResult())

	if f.Confidence != 1.0 {
		t.Errorf("Expected confidence capped at 1.0, got %f", f.Confidence)
	}
}

// --- Test: verifyFindingsWithAuth edge cases ---

func TestVerifyFindings_EmptyFindings(t *testing.T) {
	engine := makeTestEngine()
	result := engine.verifyFindingsWithAuth(context.Background(), []model.Finding{}, nil)
	if len(result) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(result))
	}
}

// --- Helpers ---

// fakeExecResult holds the same fields as execverify.ExecutionResult
// so tests can construct results without importing execverify.
type fakeExecResult struct {
	executed     bool
	dialogType   string
	confidence   float64
	domMutations []string
}

func (r *fakeExecResult) toExecverifyResult() *execverify.ExecutionResult {
	return &execverify.ExecutionResult{
		Executed:      r.executed,
		DialogType:    r.dialogType,
		Confidence:    r.confidence,
		DOMMutations:  r.domMutations,
	}
}

func makeTestEngine() *Engine {
	ssrfguard.AllowPrivate = true
	return &Engine{
		config: Config{
			ConfidenceMin: verify.DefaultConfidenceThreshold,
			RateLimit:     100,
		},
		client:     httpclient.NewClient(30*time.Second, nil),
		verifier:   verify.NewVerifier(),
		throttle:   NewThrottle(100, 200, false),
		logger:     zap.NewNop(),
		wafTracker: &WAFTracker{},
	}
}

func makeTestInjection(target model.Target) model.InjectionPoint {
	return model.InjectionPoint{
		Target: target,
		Parameter: model.Parameter{
			Name: "q",
			Type: model.ParamQuery,
		},
		Contexts: []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}
}
