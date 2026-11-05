package integration

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
	"github.com/wqnmlgb151/XSSscan/pkg/blind"
	"github.com/wqnmlgb151/XSSscan/pkg/callback"
	"github.com/wqnmlgb151/XSSscan/pkg/dom"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/scanner"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/pkg/stored"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
)

func TestCustomMarkerPrefixPreservesFourDetectors(t *testing.T) {
	for _, module := range []string{"reflected", "dom", "stored", "blind"} {
		t.Run(module, func(t *testing.T) {
			if module == "dom" && testing.Short() {
				t.Skip("real Chrome required")
			}
			ctx, cancel := context.WithTimeout(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 60*time.Second)
			defer cancel()
			ctx, err := analyze.WithMarkerPrefix(ctx, "auditmarker")
			if err != nil {
				t.Fatal(err)
			}
			callbacks := callback.NewServer("127.0.0.1:0")
			if err := callbacks.Start(); err != nil {
				t.Fatal(err)
			}
			defer callbacks.Stop()
			var observed atomic.Int64
			var mu sync.Mutex
			saved := ""
			token := regexp.MustCompile(`xsscan=(auditmarker[a-z0-9]+)`)
			callbackClient := &http.Client{Timeout: time.Second}
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				value := r.URL.Query().Get("q")
				if strings.Contains(value, "auditmarker") {
					observed.Add(1)
				}
				w.Header().Set("Content-Type", "text/html")
				switch module {
				case "stored":
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
				case "blind":
					if match := token.FindStringSubmatch(value); len(match) > 0 {
						response, err := callbackClient.Get(callbacks.BaseURL() + "/?xsscan=" + match[1])
						if err != nil {
							t.Errorf("loopback callback: %v", err)
						} else {
							response.Body.Close()
						}
					}
					fmt.Fprint(w, "no reflection")
					return
				case "dom":
					fmt.Fprint(w, `<div id=out></div><script>document.getElementById('out').innerHTML=new URLSearchParams(location.search).get('q')||'';</script>`)
					return
				}
				fmt.Fprint(w, "<body>"+value+"</body>")
			}))
			defer server.Close()
			target := model.Target{URL: server.URL + "/?q=x"}
			var findings []model.Finding
			switch module {
			case "reflected":
				engine := scanner.NewEngine(scanner.Config{Concurrency: 4, RateLimit: 1000, RateBurst: 100, MaxPayloads: 4, RequestTimeout: 5 * time.Second}, nil, server.Client())
				result, scanErr := engine.Run(ctx, target)
				err = scanErr
				if result != nil {
					findings = result.Findings
				}
			case "dom":
				detector, openErr := dom.NewScanner(ctx, 20*time.Second)
				err = openErr
				if err == nil {
					defer detector.Close()
					findings, err = detector.DetectPayloads(ctx, target, []string{`<img src=x onerror=alert(1)>`})
				}
			case "stored":
				target.URL = server.URL + "/save?q=x"
				detector := stored.NewScanner(server.Client(), stored.Config{TriggerURLs: []string{server.URL + "/view"}, MaxPolls: 1, PollingInterval: time.Millisecond}, nil)
				findings, err = detector.DetectWithError(ctx, []stored.Injection{{Target: target, Parameter: model.Parameter{Name: "q", Type: model.ParamQuery}}})
			case "blind":
				detector := blind.New(server.Client(), blind.Config{Callback: callbacks.BaseURL(), Observe: func(context.Context) ([]callback.Callback, error) { return callbacks.Callbacks(), nil }})
				result, scanErr := detector.Scan(ctx, target)
				err = scanErr
				if result != nil {
					findings = result.Findings
				}
			}
			if err != nil || len(findings) == 0 || observed.Load() == 0 {
				t.Fatalf("%s custom prefix coverage findings=%d markers=%d error=%v", module, len(findings), observed.Load(), err)
			}
		})
	}
}
