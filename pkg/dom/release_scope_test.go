package dom

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplayUsesSameOriginPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}

	var foreignHits atomic.Int32
	foreign := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits.Add(1) }))
	defer foreign.Close()
	seed := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jump" {
			http.Redirect(w, r, foreign.URL, http.StatusFound)
			return
		}
		fmt.Fprint(w, "<body>ready</body>")
	}))
	defer seed.Close()
	s, _ := NewScanner(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 10*time.Second)
	defer s.Close()
	if err := s.CheckTarget(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: seed.URL}); err != nil {
		t.Fatal(err)
	}
	got := s.replayDOMCandidate(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: seed.URL + "/jump"}, model.Finding{}, replayDescriptor{Source: replaySourceFragment}, "plain")
	if got.Outcome != replayError || foreignHits.Load() != 0 {
		t.Fatalf("replay escaped scope: %+v hits=%d", got, foreignHits.Load())
	}
}

func TestReplayRetainsAuthenticationSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}

	var rejected atomic.Int32
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "target-identity" || r.Header.Get("Authorization") != "Bearer fixture" {
			rejected.Add(1)
			http.Error(w, "wrong identity", 401)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body><div id="out"></div><script>document.getElementById('out').innerHTML=decodeURIComponent(location.hash.slice(1));</script></body>`)
	}))
	defer server.Close()
	s, _ := NewScannerWithAuth(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 10*time.Second, &AuthState{Cookies: []*http.Cookie{{Name: "session", Value: "fallback-identity"}}})
	defer s.Close()
	target := model.Target{URL: server.URL, Headers: map[string]string{"Authorization": "Bearer fixture"}, Cookies: []*http.Cookie{{Name: "session", Value: "target-identity"}}}
	if err := s.CheckTarget(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), target); err != nil {
		t.Fatal(err)
	}
	got := s.replayDOMCandidate(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), target, model.Finding{}, replayDescriptor{Source: replaySourceFragment}, "plain-text")
	if got.Outcome != replayReachedPlain || rejected.Load() != 0 {
		t.Fatalf("replay changed authentication: %+v rejected=%d", got, rejected.Load())
	}
}
