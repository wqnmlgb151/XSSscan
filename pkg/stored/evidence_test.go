package stored

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"html"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
	"github.com/wqnmlgb151/XSSscan/pkg/browser"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestStoredUnknownJavaScriptDiagnostic(t *testing.T) {
	marker := analyze.GenerateMarker()
	candidates, problems := storedPayloadsWithDiagnostics(Injection{Marker: marker}, []*triggerObservation{{url: "http://local/view", body: `<script>import x from 'module'; const q='` + marker + `';</script>`}})
	if len(candidates) != 0 || len(problems) == 0 || !strings.Contains(problems[0].Error(), "http://local/view") {
		t.Fatalf("unsupported syntax silently treated clean: candidates=%+v problems=%+v", candidates, problems)
	}
}

func TestStoredEvidenceStructuralGate(t *testing.T) {

	for _, mode := range []string{"escaped", "textarea", "json", "plain", "stripped", "html"} {
		t.Run(mode, func(t *testing.T) {
			var saved atomic.Value
			saved.Store("")
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				if r.URL.Path == "/save" {
					saved.Store(r.FormValue("q"))
					return
				}
				value := saved.Load().(string)
				switch mode {
				case "escaped":
					fmt.Fprint(w, "<p>"+html.EscapeString(value)+"</p>")
				case "textarea":
					fmt.Fprint(w, "<textarea>"+value+"</textarea>")
				case "json":
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, "%q", value)
				case "plain":
					w.Header().Set("Content-Type", "text/plain")
					fmt.Fprint(w, value)
				case "stripped":
					if strings.Contains(value, "<") {
						value = "filtered"
					}
					fmt.Fprint(w, "<p>"+value+"</p>")
				default:
					fmt.Fprint(w, "<p>"+value+"</p>")
				}
			}))
			defer server.Close()
			s := NewScanner(server.Client(), Config{TriggerURLs: []string{server.URL + "/view"}, MaxPolls: 1}, nil)
			marker := analyze.GenerateMarker()
			got, err := s.DetectWithError(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), []Injection{{Target: model.Target{URL: server.URL + "/save?q=test"}, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}, Marker: marker}})
			if err != nil {
				t.Fatal(err)
			}
			if mode != "html" {
				if len(got) != 0 {
					t.Fatalf("inert persistence reported: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Payload == marker || got[0].ExecutionVerified || got[0].Confidence > 0.90 || got[0].Evidence.TriggerURL != server.URL+"/view" || got[0].Evidence.DetectionMethod != "stored_context" {
				t.Fatalf("bad structural evidence: %+v", got)
			}
		})
	}
}

func TestStoredBrowserEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	if _, err := browser.FindChrome(); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{"html", "double-attr", "single-attr", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			var saved atomic.Value
			saved.Store("")
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookie, err := r.Cookie("session")
				if r.Header.Get("Authorization") != "Bearer proof" || err != nil || cookie.Value != "secret" {
					http.Error(w, "auth missing", 401)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				if r.URL.Path == "/save" {
					if r.Method != "POST" || r.FormValue("csrf") != "keep" {
						http.Error(w, "body lost", 400)
						return
					}
					saved.Store(r.FormValue("q"))
					return
				}
				if mode == "blocked" {
					w.Header().Set("Content-Security-Policy", "script-src 'nonce-proof'")
				}
				fmt.Fprint(w, `<html><body><script nonce="proof">alert('unrelated')</script>`)
				switch mode {
				case "double-attr":
					fmt.Fprintf(w, `<input value="%s">`, saved.Load().(string))
				case "single-attr":
					fmt.Fprintf(w, `<input value='%s'>`, saved.Load().(string))
				default:
					fmt.Fprint(w, saved.Load().(string))
				}
				fmt.Fprint(w, "</body></html>")
			}))
			defer server.Close()
			target := model.Target{URL: server.URL + "/save", Method: "POST", Body: "q=test&csrf=keep", Headers: map[string]string{"Authorization": "Bearer proof", "Content-Type": "application/x-www-form-urlencoded"}, Cookies: []*http.Cookie{{Name: "session", Value: "secret"}}}
			s := NewScanner(server.Client(), Config{TriggerURLs: []string{server.URL + "/view"}, MaxPolls: 1, VerifyExecution: true, RequestTimeout: 15 * time.Second}, nil)
			got, err := s.DetectWithError(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), []Injection{{Target: target, Parameter: model.Parameter{Name: "q", Type: model.ParamBody}}})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].ExecutionVerified != (mode != "blocked") {
				t.Fatalf("bad execution attribution: %+v", got)
			}
			if mode != "blocked" && (got[0].Evidence.DetectionMethod != "stored_execution" || !strings.HasPrefix(got[0].Evidence.DialogMessage, analyze.MarkerPrefix)) {
				t.Fatalf("missing proof: %+v", got)
			}
			if target.Body != "q=test&csrf=keep" || target.Cookies[0].Value != "secret" {
				t.Fatal("original target changed")
			}
		})
	}
}
