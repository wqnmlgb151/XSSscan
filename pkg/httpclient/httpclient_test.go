package httpclient

import (
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"testing"
)

func TestClientMaintainsCookies(t *testing.T) {

	// Server sets a cookie on first request, expects it on second
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("session"); err == nil {
			// Cookie present — success
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("authenticated"))
		} else {
			// No cookie — set one
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("cookie set"))
		}
	}))
	defer server.Close()

	client := NewClient(0, nil, ssrfguard.Policy{AllowPrivate: true})
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}
	resp.Body.Close()

	// Second request should include the cookie
	resp2, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Second request failed: %v", err)
	}
	defer resp2.Body.Close()

	// If cookie jar works, server returns "authenticated"
	buf := make([]byte, 32)
	n, _ := resp2.Body.Read(buf)
	if string(buf[:n]) != "authenticated" {
		t.Errorf("Expected 'authenticated', got '%s' — cookie jar not working", string(buf[:n]))
	}
}
