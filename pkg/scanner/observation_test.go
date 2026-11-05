package scanner

import (
	"context"
	"encoding/json"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"html"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/pkg/verify"
)

func TestObservedNegativeResponsesAndShadowReplay(t *testing.T) {

	var calls atomic.Int32
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/encoded" {
			w.Write([]byte("<body>&lt;script&gt;alert(1)&lt;/script&gt;</body>"))
		} else {
			w.Write([]byte("<body>safe</body>"))
		}
	}))
	defer server.Close()
	e := NewEngine(Config{RateLimit: 1000, RateBurst: 1000}, nil, server.Client())
	p := payload.Payload{Value: `<script>alert(1)</script>`, Context: xctx.ContextHTMLBody}
	for _, path := range []string{"/absent", "/encoded"} {
		inj := model.InjectionPoint{Target: model.Target{URL: server.URL + path + "?q=test"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}}
		f, _, err := e.doScanPayload(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), inj, p, nil, "127.0.0.1")
		if err != nil || f != nil {
			t.Fatalf("finding=%+v err=%v", f, err)
		}
	}
	snapshot := e.observations.snapshot()
	if calls.Load() != 2 || snapshot.Total != 2 || len(snapshot.Samples) != 2 {
		t.Fatal(calls.Load(), snapshot)
	}
	if snapshot.Samples[0].Code != verify.AssessmentNotReflected || snapshot.Samples[1].Reflection != reflectionHTMLEncoded {
		t.Fatal(snapshot.Samples)
	}
	if snapshot.Samples[0].Transport.Requests != 1 || snapshot.Samples[1].RequestDigest == "" {
		t.Fatal(snapshot.Samples)
	}
	encoded, err := json.Marshal(snapshot.Samples)
	if err != nil {
		t.Fatal(err)
	}
	var replay []attemptObservation
	if err := json.Unmarshal(encoded, &replay); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(replayShadow(snapshot.Samples))
	b, _ := json.Marshal(replayShadow(replay))
	if string(a) != string(b) || calls.Load() != 2 {
		t.Fatal("replay changed decisions or sent traffic")
	}
}

func TestObservationBoundsCopiesAndReset(t *testing.T) {
	var log observationLog
	var wg sync.WaitGroup
	for i := range 80 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.record(attemptObservation{ID: uint64(i + 1), PathID: "one", Code: verify.AssessmentNotReflected, Payload: strings.Repeat("p", 5000), Snippet: strings.Repeat("s", 5000)})
		}()
	}
	wg.Wait()
	s := log.snapshot()
	if s.Total != 80 || len(s.Samples) != maxPathSamples || s.DroppedSamples != 80-maxPathSamples {
		t.Fatal(s)
	}
	for _, item := range s.Samples {
		if len(item.Payload)+len(item.Snippet) > 1024 {
			t.Fatal("unbounded sample")
		}
	}
	s.Samples[0].Payload = "changed"
	s.ByCode[verify.AssessmentNotReflected] = 0
	if log.snapshot().Samples[0].Payload == "changed" || log.snapshot().ByCode[verify.AssessmentNotReflected] != 80 {
		t.Fatal("snapshot aliases mutable state")
	}
	log.reset()
	if log.snapshot().Total != 0 || len(log.snapshot().Samples) != 0 {
		t.Fatal("cross-run observations")
	}
}

func TestObservedPolicyAndCancellationRemainUnknown(t *testing.T) {
	e := NewEngine(Config{RequestTimeout: time.Second}, nil, nil)
	ctx, cancel := context.WithCancel(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	cancel()
	inj := model.InjectionPoint{Target: model.Target{URL: "http://127.0.0.1/?q=test"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}}
	_, _, _ = e.doScanPayload(ctx, inj, payload.Payload{Value: "test"}, nil, "127.0.0.1")
	s := e.observations.snapshot()
	if len(s.Samples) != 1 || s.Samples[0].Failure == failureNone || s.Samples[0].Reflection != reflectionUnknown || replayShadow(s.Samples)[0].Action != shadowRecover {
		t.Fatal(s)
	}
}

func TestObservedRetryRedirectAndMutationLineage(t *testing.T) {

	var mu sync.Mutex
	calls := 0
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(500)
			return
		}
		if r.URL.Path == "/retry" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<body>safe</body>"))
	}))
	defer server.Close()
	e := NewEngine(Config{RateLimit: 1000, RateBurst: 1000, WAFBypass: true}, nil, server.Client())
	p := payload.Payload{Value: `<script>alert(1)</script>`, Context: xctx.ContextHTMLBody}
	inj := model.InjectionPoint{Target: model.Target{URL: server.URL + "/retry?q=test"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}}
	f, err := e.scanPayload(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), inj, p, nil, "127.0.0.1", pathID(""))
	if f != nil || err != nil {
		t.Fatal(f, err)
	}
	s := e.observations.snapshot()
	if len(s.Samples) < 2 || s.Samples[0].Transport.PayloadSends != 2 || s.Samples[0].Transport.Requests != 3 || s.Samples[0].Transport.Redirects != 1 {
		t.Fatalf("retry/redirect lost: %+v", s)
	}
	requests := 0
	for i, o := range s.Samples {
		requests += o.Transport.Requests
		if i > 0 && (o.ParentID != s.Samples[0].ID || o.Kind != "mutation" || o.PathID != s.Samples[0].PathID) {
			t.Fatalf("lineage lost: %+v", o)
		}
	}
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if requests != gotCalls {
		t.Fatal("actual request count", requests, gotCalls)
	}
}

func TestObservationGlobalBoundsAndRequestIdentity(t *testing.T) {
	var log observationLog
	inj := model.InjectionPoint{Target: model.Target{URL: "http://example.invalid/path?tenant=one&q=test", Headers: map[string]string{"Authorization": "Bearer first"}}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}}
	p := payload.Payload{Value: "one"}
	first := log.begin(inj, p, 0, "payload")
	if next := log.begin(inj, p, 0, "payload"); next.PathID != first.PathID || next.ID == first.ID {
		t.Fatal("unstable identity")
	}
	for _, change := range []func(*model.InjectionPoint){
		func(i *model.InjectionPoint) { i.Target.URL = "http://example.invalid/path?tenant=two&q=test" },
		func(i *model.InjectionPoint) { i.Parameter.Type = model.ParamBody },
		func(i *model.InjectionPoint) { i.Target.Headers = map[string]string{"Authorization": "Bearer second"} },
		func(i *model.InjectionPoint) { i.Target.Cookies = []*http.Cookie{{Name: "session", Value: "other"}} },
		func(i *model.InjectionPoint) { i.Target.Headers = map[string]string{"X-Identity": "other"} },
	} {
		copy := inj
		change(&copy)
		if log.begin(copy, p, 0, "payload").PathID == first.PathID {
			t.Fatal("mixed inputs")
		}
	}
	for i := range 400 {
		o := first
		o.ID = uint64(i + 1)
		o.PathID = string(rune(i + 1))
		log.record(o)
	}
	s := log.snapshot()
	if s.Total != 400 || len(log.paths) != maxObservationPaths || len(s.Samples) != maxObservationPaths || s.DroppedSamples != 400-maxObservationPaths {
		t.Fatal(s.Total, len(log.paths), len(s.Samples))
	}
	log.reset()
	log.record(first)
	if log.snapshot().Total != 0 {
		t.Fatal("late previous-run record leaked")
	}
	for path := range 16 {
		for n := range maxPathSamples {
			o := attemptObservation{PathID: string(rune(path)), ID: uint64(path*maxPathSamples + n)}
			log.record(o)
		}
	}
	if len(log.snapshot().Samples) != maxObservationSamples || log.snapshot().Total != 16*maxPathSamples {
		t.Fatal("global sample bound")
	}
}

type observationReadFailure struct{}

func (observationReadFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (observationReadFailure) Close() error             { return nil }

func TestObservedReadErrorSurvivesSuccessfulRetry(t *testing.T) {

	calls := 0
	client := &http.Client{Transport: runTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var body io.ReadCloser = io.NopCloser(strings.NewReader("safe"))
		length := int64(4)
		if calls == 1 {
			body = observationReadFailure{}
			length = -1
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: body, ContentLength: length, Request: r}, nil
	})}
	e := NewEngine(Config{RateLimit: 1000, RateBurst: 1000}, nil, client)
	inj := model.InjectionPoint{Target: model.Target{URL: "http://127.0.0.1/?q=test"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}}
	_, _, err := e.doScanPayload(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), inj, payload.Payload{Value: "marker", Context: xctx.ContextHTMLBody}, nil, "127.0.0.1")
	s := e.observations.snapshot()
	if err != nil || len(s.Samples) != 1 || s.Samples[0].Transport.ReadErrors != 1 || s.Samples[0].Transport.PayloadSends != 2 || s.Samples[0].Failure != failureNone || s.Samples[0].ResponseIncomplete {
		t.Fatal(err, s)
	}
}

func TestObservedCSRFRefreshIncludesAuxiliaryRequest(t *testing.T) {

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Query().Get("q") == "test" {
			w.Write([]byte(`<meta name="csrf-token" content="fresh">`))
			return
		}
		if r.Header.Get("csrf-token") != "fresh" {
			w.WriteHeader(403)
			return
		}
		w.Write([]byte("safe"))
	}))
	defer server.Close()
	e := NewEngine(Config{RateLimit: 1000, RateBurst: 1000}, nil, server.Client())
	inj := model.InjectionPoint{Target: model.Target{URL: server.URL + "?q=test"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}}
	_, _, err := e.doScanPayload(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), inj, payload.Payload{Value: "marker", Context: xctx.ContextHTMLBody}, nil, "127.0.0.1")
	s := e.observations.snapshot()
	if err != nil || len(s.Samples) != 1 || s.Samples[0].Transport.Requests != 3 || s.Samples[0].Transport.PayloadSends != 2 || s.Samples[0].Status != 200 {
		t.Fatal(err, s)
	}
}

func TestObservationRunResetsWithoutChangingFindings(t *testing.T) {

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		value := r.URL.Query().Get("q")
		if r.URL.Path == "/second" {
			value = html.EscapeString(value)
		}
		w.Write([]byte("<body>" + value + "</body>"))
	}))
	defer server.Close()
	e := NewEngine(Config{RateLimit: 1000, RateBurst: 1000, MaxPayloads: 2, CSRFToken: "manual"}, nil, server.Client())
	first, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "/first?q=test"})
	if err != nil || len(first.Findings) == 0 {
		t.Fatal(first, err)
	}
	a := e.observations.snapshot()
	second, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "/second?q=test"})
	b := e.observations.snapshot()
	if err != nil || len(second.Findings) != 0 || a.Total == 0 || b.Total == 0 || b.Run <= a.Run || b.Samples[0].ID != 1 {
		t.Fatal(a, b, second, err)
	}
	for _, o := range b.Samples {
		if o.Run != b.Run {
			t.Fatal("prior run leaked")
		}
	}
}

func TestShadowDoesNotPromoteIncompleteCandidate(t *testing.T) {
	base := attemptObservation{Code: verify.AssessmentCandidate, Facts: verify.AssessmentFacts{ContextConfirmed: true}, Status: 200}
	if replayShadow([]attemptObservation{base})[0].Action != shadowVerify {
		t.Fatal("candidate suggestion lost")
	}
	for _, change := range []func(*attemptObservation){
		func(o *attemptObservation) { o.IdentityIncomplete = true },
		func(o *attemptObservation) { o.RequestDigestPartial = true },
		func(o *attemptObservation) { o.ResponseIncomplete = true },
		func(o *attemptObservation) { o.AnalysisLimited = true },
		func(o *attemptObservation) { o.ParseError = "unknown syntax" },
	} {
		o := base
		change(&o)
		if replayShadow([]attemptObservation{o})[0].Action != shadowInspect {
			t.Fatal(o)
		}
	}
}
