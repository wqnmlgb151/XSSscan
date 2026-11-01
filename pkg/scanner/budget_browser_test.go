package scanner

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/test/testenv"
	"html"
	"net/http"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/execverify"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

func TestSmallBudgetCoversLaterExecutableContext(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	for _, mode := range []string{"double-attribute", "single-attribute", "double-js", "safe"} {
		t.Run(mode, func(t *testing.T) {
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				value := r.URL.Query().Get("q")
				fmt.Fprint(w, "<body><h2>"+html.EscapeString(value)+"</h2>")
				switch mode {
				case "double-attribute":
					fmt.Fprint(w, `<input value="`+value+`">`)
				case "single-attribute":
					fmt.Fprint(w, `<input value='`+value+`'>`)
				case "double-js":
					fmt.Fprint(w, `<script>window.q="`+value+`";</script>`)
				default:
					fmt.Fprint(w, `<input value="`+html.EscapeString(value)+`">`)
				}
				fmt.Fprint(w, "</body>")
			}))
			defer server.Close()
			for _, preset := range []payload.PayloadPreset{payload.PresetStandard, payload.PresetMinimal} {
				e := NewEngine(Config{Concurrency: 2, RateLimit: 10000, RateBurst: 10000, RequestTimeout: 5 * time.Second, MaxPayloads: 8, VerifyExecution: true, VerifyTimeout: 15 * time.Second, EnableProbe: true}, zap.NewNop(), newTestClient(server.URL))
				e.SetPayloadPreset(preset)
				result, err := e.Run(context.Background(), model.Target{URL: server.URL + "?q=test"})
				if err != nil {
					t.Fatalf("preset=%s err=%v", preset, err)
				}
				if result.Stats.PayloadsSent > 8 {
					t.Fatalf("exceeded one-param budget: %+v", result.Stats)
				}
				if mode == "safe" {
					if len(result.Findings) != 0 {
						t.Fatal(result.Findings)
					}
					continue
				}
				verified := false
				for _, f := range result.Findings {
					verified = verified || f.ExecutionVerified
				}
				if !verified {
					t.Fatalf("mode=%s preset=%s findings=%+v", mode, preset, result.Findings)
				}
				t.Logf("mode=%s preset=%s payloads=%d verified=%t", mode, preset, result.Stats.PayloadsSent, verified)
			}
		})
	}
}

func TestMixedQuoteAttributeExecutes(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	for _, tc := range []struct{ quote, value string }{{`"`, `'" autofocus onfocus=alert(1) x="`}, {"'", `"' autofocus onfocus=alert(1) x='`}} {
		server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<body><input value="+tc.quote+r.URL.Query().Get("q")+tc.quote+"></body>")
		}))
		v, err := execverify.NewVerifier(context.Background(), 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		result, err := v.VerifyPayload(context.Background(), model.Target{URL: server.URL + "?q=test"}, "q", model.ParamQuery, tc.value)
		v.Close()
		server.Close()
		if err != nil || result == nil || !result.Executed {
			t.Fatalf("quote=%s value=%s result=%+v err=%v", tc.quote, tc.value, result, err)
		}
	}
}
