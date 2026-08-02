package stored

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func init() {
	ssrfguard.AllowPrivate = true
}

func TestDetect_MarkerAppearsOnTrigger(t *testing.T) {
	var submittedMarker atomic.Value
	submittedMarker.Store("")

	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marker := r.URL.Query().Get("comment")
		if marker == "" {
			marker = r.FormValue("comment")
		}
		if marker != "" {
			submittedMarker.Store(marker)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer entryServer.Close()

	var callCount atomic.Int32
	triggerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := callCount.Add(1)
		marker := submittedMarker.Load().(string)
		if count >= 3 && marker != "" {
			w.Write([]byte("<html><body>Comment: " + marker + "</body></html>"))
			return
		}
		w.Write([]byte("<html><body>No comments</body></html>"))
	}))
	defer triggerServer.Close()

	scanner := NewScanner(nil, Config{
		TriggerURLs:     []string{triggerServer.URL},
		PollingInterval: 100 * time.Millisecond,
		MaxPolls:        5,
		RequestTimeout:  5 * time.Second,
	}, nil)

	marker := analyze.GenerateMarker()
	injections := []Injection{
		{
			Target:    model.Target{URL: entryServer.URL + "?comment=test", Method: http.MethodGet},
			Parameter: model.Parameter{Name: "comment", Type: model.ParamQuery},
			Marker:    marker,
		},
	}

	findings := scanner.Detect(context.Background(), injections)
	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Type != model.StoredXSS {
		t.Errorf("Expected type StoredXSS, got %s", f.Type)
	}
	if f.Parameter != "comment" {
		t.Errorf("Expected parameter 'comment', got '%s'", f.Parameter)
	}
	if f.Confidence < 0.8 {
		t.Errorf("Expected high confidence (>=0.8), got %f", f.Confidence)
	}
	if !strings.Contains(f.Description, marker) {
		t.Errorf("Expected description to contain marker %s", marker)
	}
}

func TestDetect_MarkerNeverAppears(t *testing.T) {
	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer entryServer.Close()

	triggerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>No comments</body></html>"))
	}))
	defer triggerServer.Close()

	scanner := NewScanner(nil, Config{
		TriggerURLs:     []string{triggerServer.URL},
		PollingInterval: 50 * time.Millisecond,
		MaxPolls:        3,
		RequestTimeout:  5 * time.Second,
	}, nil)

	marker := analyze.GenerateMarker()
	injections := []Injection{
		{
			Target:    model.Target{URL: entryServer.URL + "?data=test", Method: http.MethodGet},
			Parameter: model.Parameter{Name: "data", Type: model.ParamQuery},
			Marker:    marker,
		},
	}

	findings := scanner.Detect(context.Background(), injections)
	if len(findings) != 0 {
		t.Fatalf("Expected 0 findings (marker never appeared), got %d", len(findings))
	}
}

func TestDetect_EmptyInjections(t *testing.T) {
	scanner := NewScanner(nil, Config{}, nil)
	findings := scanner.Detect(context.Background(), nil)
	if findings != nil {
		t.Errorf("Expected nil findings for empty injections, got %v", findings)
	}
}

func TestDetect_ContextCancellation(t *testing.T) {
	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer entryServer.Close()

	triggerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nothing here"))
	}))
	defer triggerServer.Close()

	scanner := NewScanner(nil, Config{
		TriggerURLs:     []string{triggerServer.URL},
		PollingInterval: 100 * time.Millisecond,
		MaxPolls:        100,
		RequestTimeout:  5 * time.Second,
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	injections := []Injection{
		{
			Target:    model.Target{URL: entryServer.URL + "?x=test", Method: http.MethodGet},
			Parameter: model.Parameter{Name: "x", Type: model.ParamQuery},
			Marker:    analyze.GenerateMarker(),
		},
	}

	findings := scanner.Detect(ctx, injections)
	if len(findings) != 0 {
		t.Fatalf("Expected 0 findings after context cancellation, got %d", len(findings))
	}
}

func TestDetect_MultipleTriggerURLs(t *testing.T) {
	var submittedMarker atomic.Value
	submittedMarker.Store("")

	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marker := r.URL.Query().Get("input")
		if marker != "" {
			submittedMarker.Store(marker)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer entryServer.Close()

	trigger1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("empty"))
	}))
	defer trigger1.Close()

	trigger2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marker := submittedMarker.Load().(string)
		w.Write([]byte("Stored: " + marker))
	}))
	defer trigger2.Close()

	scanner := NewScanner(nil, Config{
		TriggerURLs:     []string{trigger1.URL, trigger2.URL},
		PollingInterval: 50 * time.Millisecond,
		MaxPolls:        3,
		RequestTimeout:  5 * time.Second,
	}, nil)

	marker := analyze.GenerateMarker()
	injections := []Injection{
		{
			Target:    model.Target{URL: entryServer.URL + "?input=test", Method: http.MethodGet},
			Parameter: model.Parameter{Name: "input", Type: model.ParamQuery},
			Marker:    marker,
		},
	}

	findings := scanner.Detect(context.Background(), injections)
	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding (found on second trigger URL), got %d", len(findings))
	}
}

func TestDetect_BodyParameter(t *testing.T) {
	var submittedMarker atomic.Value
	submittedMarker.Store("")

	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			marker := r.FormValue("message")
			if marker != "" {
				submittedMarker.Store(marker)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer entryServer.Close()

	triggerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marker := submittedMarker.Load().(string)
		if marker != "" {
			w.Write([]byte("<p>" + marker + "</p>"))
		} else {
			w.Write([]byte("<p>no messages</p>"))
		}
	}))
	defer triggerServer.Close()

	scanner := NewScanner(nil, Config{
		TriggerURLs:     []string{triggerServer.URL},
		PollingInterval: 50 * time.Millisecond,
		MaxPolls:        3,
		RequestTimeout:  5 * time.Second,
	}, nil)

	marker := analyze.GenerateMarker()
	injections := []Injection{
		{
			Target: model.Target{
				URL:    entryServer.URL,
				Method: http.MethodPost,
				Body:   "message=hello",
				Headers: map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				},
			},
			Parameter: model.Parameter{Name: "message", Type: model.ParamBody},
			Marker:    marker,
		},
	}

	findings := scanner.Detect(context.Background(), injections)
	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for body parameter, got %d", len(findings))
	}
}

func TestCheckTriggerURL_SSRFBlocked(t *testing.T) {
	origAllow := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = false
	defer func() { ssrfguard.AllowPrivate = origAllow }()

	scanner := NewScanner(nil, Config{
		RequestTimeout: 5 * time.Second,
	}, nil)

	found, err := scanner.checkTriggerURL(context.Background(), "http://127.0.0.1:9999/test", analyze.MarkerPrefix)
	if err == nil {
		t.Error("Expected SSRF error for private IP, got nil")
	}
	if found {
		t.Error("Should not return true for blocked URL")
	}
}

func TestDetect_ConcurrentWorkers(t *testing.T) {
	var submittedMarkers sync.Map

	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marker := r.URL.Query().Get("input")
		if marker != "" {
			submittedMarkers.Store(marker, true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer entryServer.Close()

	triggerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf strings.Builder
		submittedMarkers.Range(func(key, _ any) bool {
			buf.WriteString("Found: ")
			buf.WriteString(key.(string))
			buf.WriteString("\n")
			return true
		})
		w.Write([]byte(buf.String()))
	}))
	defer triggerServer.Close()

	scanner := NewScanner(nil, Config{
		TriggerURLs:     []string{triggerServer.URL},
		PollingInterval: 50 * time.Millisecond,
		MaxPolls:        3,
		RequestTimeout:  5 * time.Second,
		Concurrency:     3,
	}, nil)

	markers := make([]string, 3)
	for i := range markers {
		markers[i] = analyze.GenerateMarker()
	}
	injections := make([]Injection, 0, 3)
	for _, m := range markers {
		injections = append(injections, Injection{
			Target:    model.Target{URL: entryServer.URL + "?input=test", Method: http.MethodGet},
			Parameter: model.Parameter{Name: "input", Type: model.ParamQuery},
			Marker:    m,
		})
	}

	findings := scanner.Detect(context.Background(), injections)
	if len(findings) != 3 {
		t.Fatalf("Expected 3 findings (concurrent), got %d", len(findings))
	}
}

func TestExtractParameters_DelegatesToAnalyze(t *testing.T) {
	target := model.Target{
		URL: "http://example.com/page?name=alice&id=123",
	}
	params := ExtractParameters(target)
	if len(params) < 2 {
		t.Fatalf("Expected at least 2 params from analyze, got %d", len(params))
	}
}
