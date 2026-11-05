package scanner

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"strings"
	"testing"

	xssctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

// Model PHP ENT_COMPAT: angle brackets and double quotes are encoded,
// while a single quote can terminate a single-quoted attribute.
func TestProbeSingleQuotedAttributeENTCompat(t *testing.T) {

	for _, encodedSingle := range []bool{false, true} {
		t.Run(fmt.Sprint(encodedSingle), func(t *testing.T) {
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				value := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(r.URL.Query().Get("keyword"))
				if encodedSingle {
					value = strings.ReplaceAll(value, "'", "&#039;")
				}
				fmt.Fprintf(w, "<html><body><h2>%s</h2><input value='%s'></body></html>", value, value)
			}))
			defer server.Close()
			e := newTestEngine(server.URL)
			got := e.runContextProbe(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.InjectionPoint{Target: model.Target{URL: server.URL + "?keyword=test"}, Parameter: model.Parameter{Name: "keyword", Type: model.ParamQuery}, Contexts: []xssctx.Context{{Type: xssctx.ContextHTMLAttrValue, QuoteChar: "'"}}}, "127.0.0.1")
			if (len(got) > 0) == encodedSingle {
				t.Fatalf("contexts=%+v; encodedSingle=%v", got, encodedSingle)
			}
			// Exercise the actual analysis -> probe -> payload -> report path.
			e.config.EnableProbe = true
			e.config.MaxPayloads = 100
			e.generator.SetCustomPayloads([]payload.Payload{{Value: "' onmouseover='alert(1)' style='display:block;width:100vw;height:100vh", Context: xssctx.ContextHTMLAttrValue}})
			result, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "?keyword=test"})
			if err != nil {
				t.Fatal(err)
			}
			if !encodedSingle && (result.Stats.PayloadsSent == 0 || len(result.Findings) == 0) {
				t.Fatalf("probe lost valid candidate: %+v", result)
			}
			if encodedSingle && len(result.Findings) > 0 {
				t.Fatalf("encoded quotes reported: %+v", result.Findings)
			}
		})
	}
}
