package scanner

import (
	"context"
	"errors"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xssctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

type runTransportFunc func(*http.Request) (*http.Response, error)

func (f runTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWorkerPanicsDoNotAbandonDispatcher(t *testing.T) {

	var calls atomic.Int32
	client := &http.Client{Transport: runTransportFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) > 3 {
			panic("fixture payload failure")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader("<body>" + r.URL.Query().Get("q") + "</body>")), Request: r}, nil
	})}
	e := NewEngine(Config{Concurrency: 1, RateLimit: 10000, RateBurst: 10000, MaxPayloads: 8}, nil, client)
	ctx, cancel := context.WithTimeout(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 3*time.Second)
	defer cancel()
	result, err := e.Run(ctx, model.Target{URL: "http://127.0.0.1/?q=x"})
	if err == nil || ctx.Err() != nil || result.Stats.Status != model.ScanFailed || result.Stats.Errors < 3 {
		t.Fatalf("dispatcher abandoned or failure hidden: %+v %v", result.Stats, err)
	}
}

func TestRequestDeadlineIsFailureNotCancellation(t *testing.T) {

	client := &http.Client{Transport: runTransportFunc(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })}
	e := NewEngine(Config{}, nil, client)
	result, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: "http://127.0.0.1/?q=x"})
	if err == nil || result.Stats.Status != model.ScanFailed {
		t.Fatalf("request timeout mislabeled: %+v %v", result, err)
	}
}

func TestRunResetsTargetStateAndCountsRequests(t *testing.T) {

	var hits atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/first" {
			w.Header().Set("X-CSRF-Token", "first-token")
		} else if r.Header.Get("X-CSRF-Token") != "" {
			t.Error("CSRF leaked to second target")
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.URL.Query().Get("q"))
	}))
	defer server.Close()
	e := NewEngine(Config{Concurrency: 2, RateLimit: 10000, RateBurst: 10000, MaxPayloads: 1}, nil, server.Client())
	first, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "/first?q=x"})
	if err != nil {
		t.Fatal(err)
	}
	if int(hits.Load()) != first.Stats.RequestsSent {
		t.Fatalf("requests %d != stats %d", hits.Load(), first.Stats.RequestsSent)
	}
	e.wafTracker.Report(true, "old-waf", false)
	e.mutator.Store(payload.NewMutator())
	e.probeFiltered = 99
	before := hits.Load()
	second, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "/second?q=x"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Stats.WAF != nil || second.Stats.ProbeFiltered != 0 || second.Stats.Errors != 0 {
		t.Fatalf("state leaked: %+v", second.Stats)
	}
	if m, _ := e.mutator.Load().(*payload.Mutator); m != nil {
		t.Fatal("auto mutator leaked")
	}
	if second.Stats.RequestsSent != int(hits.Load()-before) || second.Stats.PayloadsSent != first.Stats.PayloadsSent {
		t.Fatalf("cumulative counters: first=%+v second=%+v", first.Stats, second.Stats)
	}
	if len(second.Stats.Coverage) == 0 {
		t.Fatal("missing reflected work coverage")
	}
	for _, c := range second.Stats.Coverage {
		if c.Target != server.URL+"/second?q=x" || c.Planned != c.Started+c.NotStarted || c.Started != c.Completed+c.Failed+c.Canceled {
			t.Fatalf("coverage leaked or counts diverged: %+v", c)
		}
	}
}

func TestRunWaitingCallerCanCancel(t *testing.T) {
	e := NewEngine(Config{}, nil, nil)
	e.runGate <- struct{}{}
	ctx, cancel := context.WithCancel(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	cancel()
	result, err := e.Run(ctx, model.Target{URL: "http://127.0.0.1"})
	<-e.runGate
	if !errors.Is(err, context.Canceled) || result.Stats.Status != model.ScanCanceled {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestRunCanceledDuringAnalysisReturnsResult(t *testing.T) {

	started := make(chan struct{})
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	e := NewEngine(Config{RateLimit: 1000, RateBurst: 1000}, nil, server.Client())
	ctx, cancel := context.WithCancel(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	defer cancel()
	go func() { <-started; cancel() }()
	start := time.Now()
	result, err := e.Run(ctx, model.Target{URL: server.URL + "?q=x"})
	if !errors.Is(err, context.Canceled) || result == nil || result.Stats.Status != model.ScanCanceled {
		t.Fatalf("%+v %v", result, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation delayed")
	}
}

func TestProbeHTTPFailureIsNotCleanNegative(t *testing.T) {

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	e := NewEngine(Config{RateLimit: 10000, RateBurst: 10000}, nil, server.Client())
	_, err := e.sendProbeRequest(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.InjectionPoint{Target: model.Target{URL: server.URL + "?q=x"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}}, "probe", "local")
	if err == nil || atomic.LoadInt64(&e.errors) == 0 {
		t.Fatal("probe HTTP failure swallowed")
	}
}

func TestMutationFailureRecordedWhileKeepingLaterFinding(t *testing.T) {

	var count atomic.Int32
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		w.Header().Set("Content-Type", "text/html")
		if n == 1 {
			fmt.Fprint(w, "<body>filtered</body>")
			return
		}
		if n == 2 {
			w.WriteHeader(401)
			return
		}
		fmt.Fprintf(w, "<body>%s</body>", r.URL.Query().Get("q"))
	}))
	defer server.Close()
	e := NewEngine(Config{RateLimit: 10000, RateBurst: 10000, WAFBypass: true}, nil, server.Client())
	injection := model.InjectionPoint{Target: model.Target{URL: server.URL + "?q=x"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}, Contexts: []xssctx.Context{{Type: xssctx.ContextHTMLBody}}}
	_, err := e.scanPayload(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), injection, payload.Payload{Value: `<img src=x onerror=alert(1)>`, Context: xssctx.ContextHTMLBody}, nil, "local", pathID(""))
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&e.errors) == 0 || e.firstError == nil {
		t.Fatal("mutation failure swallowed")
	}
}
