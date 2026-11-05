package stored

import (
	"context"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"html"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestPollingProgressPreservesRoundsAndCancellation(t *testing.T) {

	var requests atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte("safe"))
	}))
	defer server.Close()
	s := NewScanner(server.Client(), Config{MaxPolls: 3, PollingInterval: 10 * time.Millisecond}, nil)
	var events []model.Progress
	ctx := model.WithProgress(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), func(p model.Progress) { events = append(events, p) })
	urls := []string{server.URL + "/a", server.URL + "/b"}
	start := time.Now()
	found, err := s.pollObservations(ctx, urls, model.Target{}, "marker", "stored polling query:q")
	if err != nil || len(found) != 0 || requests.Load() != 6 || time.Since(start) < 20*time.Millisecond {
		t.Fatalf("poll budget changed: found=%v err=%v requests=%d", found, err, requests.Load())
	}
	if len(events) != 7 {
		t.Fatalf("progress=%+v", events)
	}
	for i, p := range events {
		if p.Stage != "stored polling query:q" || p.Total != 6 || p.Completed != i {
			t.Fatalf("progress=%+v", events)
		}
	}
	ctx, cancel := context.WithCancel(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	defer cancel()
	ctx = model.WithProgress(ctx, func(p model.Progress) {
		if p.Completed == 2 {
			cancel()
		}
	})
	_, err = s.pollObservations(ctx, urls, model.Target{}, "marker", "stored polling query:q")
	if err == nil || !strings.Contains(err.Error(), "canceled") || requests.Load() != 8 {
		t.Fatalf("cancel=%v requests=%d", err, requests.Load())
	}
}

func TestStoredParameterProgressDoesNotResetSameStage(t *testing.T) {

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("safe")) }))
	defer server.Close()
	s := NewScanner(server.Client(), Config{TriggerURLs: []string{server.URL + "/view"}, MaxPolls: 1, Concurrency: 2}, nil)
	var mu sync.Mutex
	stages := map[string]bool{}
	ctx := model.WithProgress(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), func(p model.Progress) { mu.Lock(); defer mu.Unlock(); stages[p.Stage] = true })
	_, err := s.DetectWithError(ctx, []Injection{
		{Target: model.Target{URL: server.URL + "/?a=x&b=x"}, Parameter: model.Parameter{Type: model.ParamQuery, Name: "a"}},
		{Target: model.Target{URL: server.URL + "/?a=x&b=x"}, Parameter: model.Parameter{Type: model.ParamQuery, Name: "b"}},
	})
	if err != nil || !stages["stored polling query:a"] || !stages["stored polling query:b"] {
		t.Fatalf("stages=%v err=%v", stages, err)
	}
}

// A trigger page that displays the marker later must not be cut off by another trigger
// page that displayed it earlier.
//
// Trigger URLs are frequently a configuration or edit page alongside the page that
// actually renders stored content, and the two do not become ready at the same time.
// Returning as soon as one round contains the marker ends the observation while the
// slower page is still about to render it, so whether a finding is reported depends on
// which page happened to be ready first.
func TestPollingIsNotCutShortByAnEarlierDisplayingTrigger(t *testing.T) {

	marker := "xsscanStoredMarker123"
	var latePolls atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/early" {
			// Ready immediately.
			w.Write([]byte("<html><body>" + marker + "</body></html>"))
			return
		}
		// The slower display page only renders the value from the third poll onwards.
		if latePolls.Add(1) >= 3 {
			w.Write([]byte("<html><body><div>" + marker + "</div></body></html>"))
			return
		}
		w.Write([]byte("<html><body>not yet</body></html>"))
	}))
	defer server.Close()
	s := NewScanner(server.Client(), Config{MaxPolls: 5, PollingInterval: 5 * time.Millisecond}, nil)
	urls := []string{server.URL + "/early", server.URL + "/late"}
	found, err := s.pollObservations(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), urls, model.Target{}, marker, "stored polling")
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	var sawLate bool
	for _, observation := range found {
		if strings.Contains(observation.url, "/late") {
			sawLate = true
		}
	}
	if !sawLate {
		t.Fatalf("the slower display page was never observed; evidence: %d pages, latePolls=%d",
			len(found), latePolls.Load())
	}
}

// Evidence must be attributed to the specific trigger page that displayed the marker,
// never to the trigger set as a whole.
func TestPollingAttributesEvidenceToTheDisplayingPage(t *testing.T) {

	marker := "xsscanAttributionMarker"
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			w.Write([]byte("<html><body>" + marker + "</body></html>"))
			return
		}
		w.Write([]byte("<html><body>nothing here</body></html>"))
	}))
	defer server.Close()
	s := NewScanner(server.Client(), Config{MaxPolls: 2, PollingInterval: 5 * time.Millisecond}, nil)
	found, err := s.pollObservations(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), []string{server.URL + "/a", server.URL + "/b"}, model.Target{}, marker, "stored polling")
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	for _, observation := range found {
		if !strings.Contains(observation.url, "/a") {
			t.Fatalf("evidence attributed to %s, which never displayed the marker", observation.url)
		}
	}
	if len(found) == 0 {
		t.Fatal("the displaying page produced no evidence")
	}
}

func TestStoredConfirmationCandidateProgress(t *testing.T) {

	var saved atomic.Value
	saved.Store("")
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/save" {
			saved.Store(r.FormValue("q"))
			return
		}
		// Marker is reflected, but each submitted executable candidate is
		// encoded. Confirmation must try the next candidate instead of winning.
		w.Write([]byte("<p>" + html.EscapeString(saved.Load().(string)) + "</p>"))
	}))
	defer server.Close()
	s := NewScanner(server.Client(), Config{TriggerURLs: []string{server.URL + "/view"}, MaxPolls: 1}, nil)
	stages := map[string]bool{}
	ctx := model.WithProgress(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), func(p model.Progress) {
		if strings.HasPrefix(p.Stage, "stored confirmation") && p.Completed == 0 {
			stages[p.Stage] = true
		}
	})
	_, err := s.DetectWithError(ctx, []Injection{{Target: model.Target{URL: server.URL + "/save?q=x"}, Parameter: model.Parameter{Type: model.ParamQuery, Name: "q"}}})
	if err != nil || len(stages) < 2 {
		t.Fatalf("candidate stages=%v err=%v", stages, err)
	}
}
