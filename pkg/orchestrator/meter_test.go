package orchestrator

import (
	"context"
	"errors"
	"github.com/xsscan/xsscan/pkg/requestbudget"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSharedMeterHTTPRedirectAndBrowserIsolation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", 302)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	m := requestbudget.New(2, 1)
	b := &BudgetTransport{Meter: m, Max: 2}
	client := &http.Client{Transport: b}
	response, err := client.Get(server.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if b.Count() != 2 || m.HTTP.Count() != 2 || m.Browser.Count() != 0 {
		t.Fatal("redirect accounting mismatch")
	}
	if !m.Browser.Take() {
		t.Fatal("Go consumed browser budget")
	}
	if _, err = client.Get(server.URL); !errors.Is(err, ErrRequestBudget) {
		t.Fatal("HTTP limit lost", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	if _, err = b.RoundTrip(req); !errors.Is(err, context.Canceled) || b.Count() != 2 {
		t.Fatal("canceled HTTP consumed budget", err)
	}
}
