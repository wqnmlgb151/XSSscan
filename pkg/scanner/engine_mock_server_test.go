package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/pkg/verify"
	"go.uber.org/zap"
)

// newMockEngine creates an Engine with nop logger, real verifier, and a
// throttle that won't interfere with tests. Caller should set AllowPrivate.
func newMockEngine() *Engine {
	ssrfguard.AllowPrivate = true
	return NewEngine(Config{
		ConfidenceMin: verify.DefaultConfidenceThreshold,
		RateLimit:     1000,
		RateBurst:     2000,
	}, zap.NewNop(), nil)
}

// --- sendWithRetry ---

func TestSendWithRetry_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	e := newMockEngine()

	inj := model.InjectionPoint{
		Target:    model.Target{URL: srv.URL + "/page?q=test", Method: "GET"},
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}
	modifiedTarget := model.Target{URL: srv.URL + "/page?q=PAYLOAD", Method: "GET"}
	p := payload.Payload{Value: "PAYLOAD", Context: ctx.ContextHTMLBody}

	resp, body, _, err := e.sendWithRetry(context.Background(), inj, modifiedTarget, p, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "<html>ok</html>" {
		t.Errorf("unexpected body: %q", string(body))
	}
}

func TestSendWithRetry_Retry5xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	e := newMockEngine()

	inj := model.InjectionPoint{
		Target:    model.Target{URL: srv.URL + "/page?q=test", Method: "GET"},
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}
	modifiedTarget := model.Target{URL: srv.URL + "/page?q=PAYLOAD", Method: "GET"}
	p := payload.Payload{Value: "PAYLOAD", Context: ctx.ContextHTMLBody}

	resp, body, _, err := e.sendWithRetry(context.Background(), inj, modifiedTarget, p, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Errorf("unexpected body: %q", string(body))
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestSendWithRetry_CSRFRefreshOn403(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "PAYLOAD") {
			// Scan request — first time 403, then succeed
			if n <= 2 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok-after-csrf"))
			return
		}
		// CSRF extraction request — serve page with token
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><form><input type="hidden" name="csrf_token" value="csrf-123"></form></body></html>`))
	}))
	defer srv.Close()

	e := newMockEngine()

	inj := model.InjectionPoint{
		Target:    model.Target{URL: srv.URL + "/page?q=test", Method: "GET"},
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}
	modifiedTarget := model.Target{URL: srv.URL + "/page?q=PAYLOAD", Method: "GET"}
	p := payload.Payload{Value: "PAYLOAD", Context: ctx.ContextHTMLBody}

	resp, body, _, err := e.sendWithRetry(context.Background(), inj, modifiedTarget, p, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "ok-after-csrf" {
		t.Errorf("unexpected body: %q", string(body))
	}
	// Verify CSRF token was extracted
	token, _ := e.csrfToken.Load().(string)
	if token != "csrf-123" {
		t.Errorf("expected CSRF token 'csrf-123', got %q", token)
	}
}

// --- buildFindingFromResponse ---

func TestBuildFindingFromResponse_Reflected(t *testing.T) {
	e := newMockEngine()

	bodyStr := `<html><body><div><img src=x onerror=alert(1)></div></body></html>`
	body := []byte(bodyStr)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}

	inj := model.InjectionPoint{
		Target:    model.Target{URL: "http://127.0.0.1/page?q=test", Method: "GET"},
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}
	p := payload.Payload{
		Value:    `<img src=x onerror=alert(1)>`,
		Context:  ctx.ContextHTMLBody,
		Severity: model.High,
	}

	finding, wafResult := e.buildFindingFromResponse(resp, body, inj.Target, inj, p, nil)
	if wafResult.Detected {
		t.Error("did not expect WAF detection")
	}
	if finding == nil {
		t.Fatal("expected finding, got nil")
	}
	if finding.Parameter != "q" {
		t.Errorf("expected parameter 'q', got %q", finding.Parameter)
	}
	if finding.Payload != p.Value {
		t.Errorf("expected payload %q, got %q", p.Value, finding.Payload)
	}
}

func TestBuildFindingFromResponse_NotReflected(t *testing.T) {
	e := newMockEngine()

	bodyStr := `<html><body>Safe content here</body></html>`
	body := []byte(bodyStr)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}

	inj := model.InjectionPoint{
		Target:    model.Target{URL: "http://127.0.0.1/page?q=test", Method: "GET"},
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}
	p := payload.Payload{
		Value:    `<img src=x onerror=alert(1)>`,
		Context:  ctx.ContextHTMLBody,
		Severity: model.High,
	}

	finding, _ := e.buildFindingFromResponse(resp, body, inj.Target, inj, p, nil)
	if finding != nil {
		t.Errorf("expected nil finding when payload not reflected, got %+v", finding)
	}
}

// --- WAF detection ---

func TestMockServer_WAFDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "abc123")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Attention Required! Cloudflare"))
	}))
	defer srv.Close()

	e := newMockEngine()

	inj := model.InjectionPoint{
		Target:    model.Target{URL: srv.URL + "/page?q=test", Method: "GET"},
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}
	modifiedTarget := model.Target{URL: srv.URL + "/page?q=PAYLOAD", Method: "GET"}
	p := payload.Payload{Value: "PAYLOAD", Context: ctx.ContextHTMLBody}

	resp, body, _, err := e.sendWithRetry(context.Background(), inj, modifiedTarget, p, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, wafResult := e.buildFindingFromResponse(resp, body, modifiedTarget, inj, p, nil)
	if !wafResult.Detected {
		t.Error("expected WAF detection")
	}
	if wafResult.Name != "Cloudflare" {
		t.Errorf("expected WAF name 'Cloudflare', got %q", wafResult.Name)
	}
}
