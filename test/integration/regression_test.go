package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/blind"
	"github.com/wqnmlgb151/XSSscan/pkg/callback"
	"github.com/wqnmlgb151/XSSscan/pkg/dom"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/scanner"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/pkg/stored"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
)

// TestRegressionBaseline is a small labeled corpus, not a population accuracy estimate.
// BASELINE records use process-wide Go allocation counters; they exclude Chrome memory.
func TestRegressionBaseline(t *testing.T) {

	for _, module := range []string{"reflected", "dom", "stored", "blind"} {
		for _, safe := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/safe=%t", module, safe), func(t *testing.T) {
				if module == "dom" && testing.Short() {
					t.Skip("real Chrome required; full CI runs this case")
				}
				var requests atomic.Int64
				var mu sync.Mutex
				saved := ""
				callbacks := callback.NewServer("127.0.0.1:0")
				if err := callbacks.Start(); err != nil {
					t.Fatal(err)
				}
				defer callbacks.Stop()
				callbackClient := &http.Client{Timeout: 5 * time.Second}
				token := regexp.MustCompile(`xsscan=([a-z0-9]+)`)
				server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					w.Header().Set("Content-Type", "text/html")
					value := r.URL.Query().Get("q")
					if module == "stored" {
						mu.Lock()
						if r.URL.Path == "/save" {
							saved = value
						}
						value = saved
						mu.Unlock()
						if r.URL.Path == "/save" {
							fmt.Fprint(w, "saved")
							return
						}
					}
					if module == "blind" {
						if match := token.FindStringSubmatch(value); len(match) > 0 {
							query := "unrelated"
							if !safe {
								query = match[1]
							}
							resp, err := callbackClient.Get(callbacks.BaseURL() + "/?xsscan=" + query)
							if err != nil {
								t.Errorf("local callback: %v", err)
							} else {
								resp.Body.Close()
							}
						}
						fmt.Fprint(w, "no reflection")
						return
					}
					if module == "dom" {
						sink := "innerHTML"
						if safe {
							sink = "textContent"
						}
						fmt.Fprintf(w, `<body><div id="out"></div><script>document.getElementById('out').%s=new URLSearchParams(location.search).get('q')||'';</script></body>`, sink)
						return
					}
					if safe {
						value = html.EscapeString(value)
					}
					fmt.Fprint(w, "<body>"+value+"</body>")
				}))
				defer server.Close()
				ctx, cancel := context.WithTimeout(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 90*time.Second)
				defer cancel()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				start := time.Now()
				var findings []model.Finding
				var err error
				target := model.Target{URL: server.URL + "/?q=test"}
				switch module {
				case "reflected":
					engine := scanner.NewEngine(scanner.Config{Concurrency: 4, RateLimit: 1000, RateBurst: 100, MaxPayloads: 4, RequestTimeout: 5 * time.Second}, nil, nil)
					var result *model.ScanResult
					result, err = engine.Run(ctx, target)
					if result != nil {
						findings = result.Findings
					}
				case "dom":
					var detector *dom.Scanner
					detector, err = dom.NewScanner(ctx, 20*time.Second)
					if err == nil {
						defer detector.Close()
						findings, err = detector.DetectPayloads(ctx, target, []string{`<img src=x onerror=alert(1)>`})
					}
				case "stored":
					target.URL = server.URL + "/save?q=test"
					detector := stored.NewScanner(server.Client(), stored.Config{TriggerURLs: []string{server.URL + "/view"}, MaxPolls: 1, PollingInterval: time.Millisecond, Concurrency: 2}, nil)
					findings, err = detector.DetectWithError(ctx, []stored.Injection{{Target: target, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}}})
				case "blind":
					detector := blind.New(server.Client(), blind.Config{Callback: callbacks.BaseURL(), Observe: func(context.Context) ([]callback.Callback, error) { return callbacks.Callbacks(), nil }})
					var result *model.ScanResult
					result, err = detector.Scan(ctx, target)
					if result != nil {
						findings = result.Findings
					}
				}
				elapsed := time.Since(start)
				runtime.ReadMemStats(&after)
				hit := len(findings) > 0
				outcome := "TN"
				if !safe {
					outcome = "FN"
					if hit {
						outcome = "TP"
					}
				} else if hit {
					outcome = "FP"
				}
				record := struct {
					Module    string  `json:"module"`
					Safe      bool    `json:"safe"`
					Outcome   string  `json:"outcome"`
					Findings  int     `json:"findings"`
					Requests  int64   `json:"target_requests"`
					Callbacks int     `json:"callback_requests"`
					WallMS    float64 `json:"wall_ms"`
					GoAlloc   uint64  `json:"go_total_alloc_bytes"`
					GoHeap    uint64  `json:"go_heap_inuse_after_bytes"`
					Error     string  `json:"error,omitempty"`
				}{Module: module, Safe: safe, Outcome: outcome, Findings: len(findings), Requests: requests.Load(), Callbacks: len(callbacks.Callbacks()), WallMS: float64(elapsed) / float64(time.Millisecond), GoAlloc: after.TotalAlloc - before.TotalAlloc, GoHeap: after.HeapInuse}
				if err != nil {
					record.Error = err.Error()
				}
				encoded, _ := json.Marshal(record)
				t.Logf("BASELINE %s", encoded)
				if err != nil || hit == safe {
					t.Fatalf("labeled fixture regression: %s (%v)", encoded, err)
				}
				if requests.Load() == 0 {
					t.Fatal("fixture was not exercised")
				}
			})
		}
	}
}
