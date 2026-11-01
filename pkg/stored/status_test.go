package stored

import (
	"context"
	"errors"
	"fmt"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestDetectWithErrorPreservesFindingAndFailures(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var saved atomic.Value
	saved.Store("unique-marker")
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if value := r.URL.Query().Get("q"); value != "" {
			saved.Store(value)
		}
		if r.URL.Path == "/broken" {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<body>"+saved.Load().(string)+"</body>")
	}))
	defer server.Close()
	s := NewScanner(server.Client(), Config{TriggerURLs: []string{server.URL + "/good", server.URL + "/broken"}, MaxPolls: 1, PollingInterval: time.Millisecond}, nil)
	inj := Injection{Target: model.Target{URL: server.URL + "?q=x"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}, Marker: "unique-marker"}
	findings, err := s.DetectWithError(context.Background(), []Injection{inj})
	if err == nil || len(findings) != 1 {
		t.Fatalf("findings=%v err=%v", findings, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.DetectWithError(ctx, []Injection{inj})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestAutoTriggerDiscoveryKeepsHealthyPagesOnPartialFailure(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var saved atomic.Value
	saved.Store("unique-marker")
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if value := r.URL.Query().Get("q"); value != "" {
			saved.Store(value)
		}
		if r.URL.Path == "/broken" {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body>`+saved.Load().(string)+`<a href="/good">good</a><a href="/broken">broken</a></body>`)
	}))
	defer server.Close()
	s := NewScanner(server.Client(), Config{MaxPolls: 1, PollingInterval: time.Millisecond}, nil)
	findings, err := s.DetectWithError(context.Background(), []Injection{{Target: model.Target{URL: server.URL + "?q=x"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}, Marker: "unique-marker"}})
	if err == nil || len(findings) != 1 {
		t.Fatalf("partial crawl erased usable triggers: findings=%d err=%v", len(findings), err)
	}
}

func TestAutoTriggerRequiresIndependentQueryDisplay(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<body>no display links</body>")
	}))
	defer server.Close()
	s := NewScanner(server.Client(), Config{}, nil)
	urls, err := s.discoverTriggerURLs(context.Background(), server.URL+"?q=original", nil)
	if err == nil || len(urls) > 0 {
		t.Fatalf("query entry became its own trigger: %v %v", urls, err)
	}
}

func TestAutomaticTriggerSeedAliases(t *testing.T) {
	seed, _ := url.Parse("https://example.com/save?q=original&id=1#fragment")
	for _, u := range []string{"https://example.com/save?id=1&q=original", "https://example.com:443/save?q=original", "https://example.com/save/?q=different", "https://example.com/save?q=original#other"} {
		if !automaticTriggerReplaysSeed(seed, u) {
			t.Fatalf("submission alias allowed: %s", u)
		}
	}
	for _, u := range []string{"https://example.com/view?q=original", "https://example.com/save", "https://other.example/save?q=original"} {
		if automaticTriggerReplaysSeed(seed, u) {
			t.Fatalf("independent display rejected: %s", u)
		}
	}
}
