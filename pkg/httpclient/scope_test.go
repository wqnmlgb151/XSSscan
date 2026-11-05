package httpclient

import (
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestRedirectScopeDoesNotForwardCredentials(t *testing.T) {

	var foreignHits atomic.Int32
	foreign := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits.Add(1) }))
	defer foreign.Close()
	origin := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		if r.URL.Path == "/ok" {
			if r.Header.Get("Authorization") != "Bearer exact" {
				t.Error("lost same-origin auth")
			}
			return
		}
		http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	client := NewClient(0, nil, ssrfguard.Policy{AllowPrivate: true})
	defer client.CloseIdleConnections()
	for _, path := range []string{"/cross", "/same"} {
		req, _ := http.NewRequest(http.MethodGet, origin.URL+path, nil)
		req.Header.Set("Authorization", "Bearer exact")
		req.Header.Set("Cookie", "session=exact")
		req.Header.Set("X-API-Key", "exact")
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		if path == "/cross" && err == nil {
			t.Fatal("cross-origin redirect accepted")
		}
		if path == "/same" && err != nil {
			t.Fatal(err)
		}
	}
	if foreignHits.Load() != 0 {
		t.Fatal("foreign origin received a request")
	}
}

func TestInitialPrivateRequestBlocked(t *testing.T) {

	var hits atomic.Int32
	server := testenv.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer server.Close()
	client := NewClient(0, nil, ssrfguard.Policy{AllowPrivate: false})
	defer client.CloseIdleConnections()
	resp, err := client.Get(server.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || hits.Load() != 0 {
		t.Fatal("unguarded initial request")
	}
}
