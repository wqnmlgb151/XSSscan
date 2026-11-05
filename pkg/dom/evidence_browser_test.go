package dom

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/browser"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestDOMBrowserEvidenceAttribution(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	if _, err := browser.FindChrome(); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, script string
		want         bool
	}{
		{"plain", "", false},
		{"console-only", `console.log(decodeURIComponent(location.hash));`, false},
		{"textContent", `document.body.textContent=decodeURIComponent(location.hash);`, false},
		{"target-sink", `document.body.innerHTML=decodeURIComponent(location.hash.slice(1));`, true},
		{"long-sink", `document.body.innerHTML="a".repeat(500)+decodeURIComponent(location.hash.slice(1));`, true},
		{"missing-hooks", `delete window.__xsscan_hooks;`, false},
		{"overflowed-records", `window.__xsscan_hooks_overflowed = true; localStorage.setItem("x", decodeURIComponent(location.hash.slice(1)));`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, "<html><body>safe<script>%s</script></body></html>", tc.script)
			}))
			defer server.Close()
			scanner, err := NewScanner(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 15*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer scanner.Close()
			marker := "xsscanAttribution123"
			u, _ := url.Parse(server.URL)
			test := domXSSTest{Name: "fragment", Source: "location.hash", NavURL: buildURLWithFragment(u, marker)}
			findings, err := scanner.runSingleDOMTest(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL}, test, marker, marker)
			if tc.name == "missing-hooks" {
				if err == nil || len(findings) > 0 {
					t.Fatalf("missing hooks must fail: %v %+v", err, findings)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (len(findings) > 0) != tc.want {
				t.Fatalf("findings=%+v want=%v", findings, tc.want)
			}
			if tc.want && findings[0].ExecutionVerified {
				t.Fatal("sink flow is not execution proof")
			}
			// The old inline-event test injected its own onerror on every safe page.
			if tc.name == "plain" {
				findings, err = scanner.runSingleDOMTest(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL}, domXSSTest{Name: "inline-event", Source: "legacy", NavURL: server.URL, Extra: "inject-inline-" + marker}, marker, marker)
				if err != nil || len(findings) > 0 {
					t.Fatalf("self injection: %v %+v", err, findings)
				}
			}
		})
	}
}

func TestDOMBrowserPrivateTargetBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	if _, err := browser.FindChrome(); err != nil {
		t.Fatal(err)
	}

	var hits atomic.Int32
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "safe") }))
	defer server.Close()
	scanner, err := NewScanner(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: false}), 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	findings, err := scanner.runSingleDOMTest(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: false}), model.Target{URL: server.URL}, domXSSTest{Name: "fragment", NavURL: server.URL + "#xsscanBlocked"}, "xsscanBlocked", "xsscanBlocked")
	if err == nil || len(findings) > 0 || hits.Load() != 0 {
		t.Fatalf("err=%v findings=%+v hits=%d", err, findings, hits.Load())
	}
}
