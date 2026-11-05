package dom

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestDOMCookieSeedAndNavigationAreNotSinks(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	for _, script := range []string{"", "document.cookie=document.cookie", "document.body.textContent=document.cookie", "history.replaceState({},'',location.hash)"} {
		t.Run(script, func(t *testing.T) {
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, "<body><script>%s</script></body>", script)
			}))
			defer server.Close()
			s, _ := NewScanner(context.Background(), 15*time.Second)
			defer s.Close()
			u, _ := url.Parse(server.URL)
			for _, probe := range buildDOMTests(u, "<img src=x onerror=alert(1)>", "xsscanCookieTest123") {
				if probe.Name != "document-cookie" {
					continue
				}
				found, err := s.runSingleDOMTest(context.Background(), model.Target{URL: server.URL}, probe, "xsscanCookieTest123", "<img src=x onerror=alert(1)>")
				if err != nil || len(found) != 0 {
					t.Fatalf("self/benign operation reported: %v %+v", err, found)
				}
			}
		})
	}
}

func TestDOMBrowserContextIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body><script>document.body.innerHTML=document.cookie+(localStorage.getItem('probe')||'')</script></body>`)
	}))
	defer server.Close()
	s, _ := NewScanner(context.Background(), 15*time.Second)
	defer s.Close()
	target := model.Target{URL: server.URL}
	const marker = "xsscanIsolation123"
	seed := domXSSTest{Name: "seed", NavURL: server.URL, Extra: `document.cookie='probe=xsscanIsolation123';localStorage.setItem('probe','xsscanIsolation123')`}
	first, err := s.runSingleDOMTest(context.Background(), target, seed, marker, marker)
	if err != nil || len(first) == 0 {
		t.Fatalf("seed lost: %v %+v", err, first)
	}
	second, err := s.runSingleDOMTest(context.Background(), target, domXSSTest{Name: "clean", NavURL: server.URL}, marker, marker)
	if err != nil || len(second) != 0 {
		t.Fatalf("state leaked between contexts: %v %+v", err, second)
	}
	if s.browserCtx == nil {
		t.Fatal("shared browser not initialized")
	}
}

func TestDOMFindingsAggregateBySourceAndSink(t *testing.T) {
	var input []model.Finding
	for _, sink := range []string{"innerHTML", "eval"} {
		for _, value := range []string{"a", "b", "a"} {
			input = append(input, model.Finding{URL: "http://local/?x=1#probe", Parameter: "DOM (fragment)", Payload: value, Evidence: model.Evidence{Context: sink}})
		}
	}
	got := aggregateDOMFindings(input)
	if len(got) != 2 || strings.Join(got[0].Payloads, ",") != "a,b" {
		t.Fatalf("bad aggregation: %+v", got)
	}
}

func TestDOMMatrixConcurrencyAndCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	for _, cancelDuringRun := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelDuringRun), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var active, peak atomic.Int32
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/favicon.ico" {
					w.WriteHeader(204)
					return
				}
				n := active.Add(1)
				defer active.Add(-1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				if cancelDuringRun {
					cancel()
				}
				select {
				case <-time.After(100 * time.Millisecond):
				case <-r.Context().Done():
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, "<body>safe</body>")
			}))
			defer server.Close()
			var mu sync.Mutex
			completed := 0
			ctx = model.WithProgress(ctx, func(p model.Progress) { mu.Lock(); defer mu.Unlock(); completed = max(completed, p.Completed) })
			s, _ := NewScanner(context.Background(), 10*time.Second)
			defer s.Close()
			found, coverage, err := s.DetectPayloadsWithCoverage(ctx, model.Target{URL: server.URL}, []string{"<img src=x onerror=alert(1)>", "<script>alert(1)</script>"})
			if coverage.Started != coverage.Completed+coverage.Failed+coverage.Canceled || (coverage.PlannedKnown && coverage.Planned != coverage.Started+coverage.NotStarted) {
				t.Fatalf("invalid coverage: %+v", coverage)
			}
			if len(found) != 0 {
				t.Fatalf("safe matrix found vulnerabilities: %+v", found)
			}
			if cancelDuringRun {
				if err == nil {
					t.Fatal("cancellation discarded")
				}
				found, err = s.runSingleDOMTest(context.Background(), model.Target{URL: server.URL}, domXSSTest{Name: "retry", NavURL: server.URL}, "xsscanRetry123", "")
				if err != nil || len(found) != 0 {
					t.Fatalf("shared browser unusable after cancellation: %v %+v", err, found)
				}
				cleanup, finish := context.WithTimeout(s.browserCtx, time.Second)
				defer finish()
				contexts, _, err := target.GetBrowserContexts().Do(cdp.WithExecutor(cleanup, chromedp.FromContext(s.browserCtx).Browser))
				if err != nil || len(contexts) != 0 {
					t.Fatalf("browser contexts leaked: %v %v", contexts, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			done := completed
			mu.Unlock()
			if done != 20 || coverage.Planned != 20 || coverage.Completed != 20 || peak.Load() < 2 || peak.Load() > 4 {
				t.Fatalf("done=%d peak=%d", done, peak.Load())
			}
		})
	}
}
