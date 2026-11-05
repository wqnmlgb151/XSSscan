package blind

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/wqnmlgb151/XSSscan/pkg/callback"
	"github.com/wqnmlgb151/XSSscan/pkg/httpclient"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestBlindWithoutReflectionAndCorrelation(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var submissions int
	var observed []callback.Callback
	tokenRe := regexp.MustCompile(`xsscan=([a-z0-9]+)`)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		submissions++
		if match := tokenRe.FindStringSubmatch(r.URL.Query().Get("q")); len(match) > 0 {
			observed = append(observed, callback.Callback{Query: "xsscan=" + match[1]})
		}
		w.WriteHeader(500)
		fmt.Fprint(w, "no reflection")
	}))
	defer server.Close()
	s := New(httpclient.NewClient(0, nil), Config{Callback: "http://callback.test/", Observe: func(context.Context) ([]callback.Callback, error) {
		return append(observed, callback.Callback{Query: "xsscan=unrelated"}), nil
	}})
	result, err := s.Scan(context.Background(), model.Target{URL: server.URL + "?q=x"})
	if err == nil || result.Stats.Status != model.ScanPartial || submissions == 0 || len(result.Findings) != 3 || result.Findings[0].Parameter != "q" || result.Findings[0].ExecutionVerified {
		t.Fatalf("blind result: %+v %v", result, err)
	}
	u, _ := url.Parse(result.Findings[0].URL)
	if u.Host == "callback.test" {
		t.Fatal("finding lost target")
	}
}

func TestExternalCallbackRemainsIncomplete(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer server.Close()
	result, err := New(httpclient.NewClient(0, nil), Config{Callback: "dns.example.test"}).Scan(context.Background(), model.Target{URL: server.URL + "?q=x"})
	if err == nil || result.Stats.Status != model.ScanPartial || result.Stats.PayloadsSent == 0 {
		t.Fatalf("unobserved callback reported complete: %+v %v", result, err)
	}
}
