package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"html"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

func TestFilterIsolationAcrossParameters(t *testing.T) {

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<div>"+html.EscapeString(r.URL.Query().Get("a"))+"</div><div>"+r.URL.Query().Get("b")+"</div>")
	}))
	defer server.Close()
	e := NewEngine(Config{Concurrency: 2, RateLimit: 10000, RateBurst: 10000, RequestTimeout: 5 * time.Second, MaxPayloads: 10}, zap.NewNop(), newTestClient(server.URL))
	e.generator.SetCustomPayloads([]payload.Payload{{Value: "SAFE", Type: payload.PayloadTypeCustom}})
	got, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "?a=x&b=x"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range got.Findings {
		if f.Parameter == "a" {
			t.Fatal("escaped parameter reported vulnerable")
		}
		if f.Parameter == "b" && strings.Contains(f.Payload, "<") {
			found = true
		}
	}
	if !found {
		t.Fatalf("one parameter's filter pruned another: %+v", got)
	}
}

func TestUnknownJSAnalysisIsIncomplete(t *testing.T) {

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script>import x from 'm';let a='`+r.URL.Query().Get("q")+`';</script>`)
	}))
	defer server.Close()
	e := NewEngine(Config{Concurrency: 1, RateLimit: 1000, RateBurst: 1000}, zap.NewNop(), newTestClient(server.URL))
	got, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "?q=x"})
	if err == nil || got.Stats.Status == model.ScanCompleted || len(got.Stats.Issues) == 0 || len(got.Findings) != 0 {
		t.Fatalf("unknown JS reported clean/valid: %+v %v", got, err)
	}
}

func TestJSASTBrowserCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome corpus")
	}

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		script := ""
		switch r.URL.Path {
		case "/regex":
			script = "let r=/" + q + "/;"
		case "/regex-class":
			script = "let r=/[" + q + "]/;"
		case "/template":
			script = "let x=`" + q + "`;"
		case "/nested":
			script = "let x=`${`" + q + "`}`;"
		case "/block":
			script = "/*" + q + "*/"
		case "/line":
			script = "//" + q + "\n"
		case "/handler":
			fmt.Fprint(w, `<html><body><input value='`+q+`'></body></html>`)
			return
		case "/escaped":
			encoded, _ := json.Marshal(q)
			script = "let x=" + string(encoded) + ";"
		case "/invalid":
			script = "if ( let x='" + q + "';"
		case "/module":
			script = "export const x='" + q + "';"
		case "/module-await":
			script = "await Promise.resolve(); export const x=`" + q + "`;"
		case "/module-escaped":
			encoded, _ := json.Marshal(q)
			script = "export const x=" + string(encoded) + ";"
		case "/module-invalid-strict":
			script = "with({}){}; export const x='" + q + "';"
		}
		tag := "<script>"
		if strings.HasPrefix(r.URL.Path, "/module") {
			tag = `<script type="module">`
		}
		fmt.Fprint(w, "<html><body>"+tag+script+"</script></body></html>")
	}))
	defer server.Close()
	for _, tc := range []struct {
		path     string
		positive bool
	}{{"regex", true}, {"regex-class", true}, {"template", true}, {"nested", true}, {"block", true}, {"line", true}, {"handler", true}, {"escaped", false}, {"invalid", false}, {"module", true}, {"module-await", true}, {"module-escaped", false}, {"module-invalid-strict", false}} {
		t.Run(tc.path, func(t *testing.T) {
			e := NewEngine(Config{Concurrency: 2, RateLimit: 10000, RateBurst: 10000, RequestTimeout: 5 * time.Second, MaxPayloads: 8, VerifyExecution: true, VerifyTimeout: 20 * time.Second}, zap.NewNop(), newTestClient(server.URL))
			got, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "/" + tc.path + "?q=x"})
			if !strings.Contains(tc.path, "invalid") && err != nil {
				t.Fatal(err)
			}
			verified := false
			for _, f := range got.Findings {
				if f.ExecutionVerified {
					verified = true
				}
			}
			if tc.positive && !verified || !tc.positive && len(got.Findings) > 0 {
				t.Fatalf("browser label mismatch positive=%t: %+v %v", tc.positive, got, err)
			}
			t.Logf("positive=%t findings=%d execution_verified=%t status=%s", tc.positive, len(got.Findings), verified, got.Stats.Status)
		})
	}
}
