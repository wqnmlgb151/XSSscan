package scanner

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"html"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/execverify"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

// Replay the reported URL verbatim, without changing the payload or alert argument.
// These local fixtures contain no unrelated dialogs, so alert("1") is unambiguous.
func TestReportedPOCReproducesWithoutInstrumentation(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	for _, mode := range []string{"body", "attr", "escaped"} {
		t.Run(mode, func(t *testing.T) {
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				value := r.URL.Query().Get("q")
				switch mode {
				case "body":
					fmt.Fprint(w, "<body>"+value+"</body>")
				case "attr":
					fmt.Fprint(w, `<body><h2>`+html.EscapeString(value)+`</h2><input value="`+value+`"></body>`)
				case "escaped":
					fmt.Fprint(w, "<body>"+html.EscapeString(value)+"</body>")
				}
			}))
			defer server.Close()
			engine := NewEngine(Config{Concurrency: 2, RateLimit: 10000, RateBurst: 10000, RequestTimeout: 5 * time.Second, VerifyExecution: true, VerifyTimeout: 15 * time.Second, EnableProbe: true}, zap.NewNop(), newTestClient(server.URL))
			result, err := engine.Run(context.Background(), model.Target{URL: server.URL + "?q=test"})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "escaped" {
				if len(result.Findings) != 0 {
					t.Fatalf("encoded negative reported: %+v", result.Findings)
				}
				return
			}
			if len(result.Findings) == 0 {
				t.Fatal("no finding on positive fixture")
			}
			verifier, _ := execverify.NewVerifier(context.Background(), 15*time.Second)
			defer verifier.Close()
			for _, finding := range result.Findings {
				if !finding.ExecutionVerified {
					t.Fatalf("positive not verified: %+v", finding)
				}
				parsed, _ := url.Parse(finding.URL)
				if parsed.Query().Get("q") != finding.Payload {
					t.Fatalf("URL/payload mismatch: %+v", finding)
				}
				reproduced, err := verifier.VerifyStoredPage(context.Background(), model.Target{URL: finding.URL}, "1")
				if err != nil || !reproduced.Executed {
					t.Fatalf("reported original payload does not reproduce: %+v %v %+v", finding, err, reproduced)
				}
			}
		})
	}
}
