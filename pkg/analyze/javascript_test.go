package analyze

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"testing"

	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestAnalysisSinglePointKeepsAllJSOccurrences(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<script>let a='%s'; let b=\"%s\"; let c=`${%s()}`; let d=/%s/;</script>", q, q, q, q)
	}))
	defer server.Close()
	got, err := NewAnalyzer(server.Client()).Analyze(context.Background(), model.Target{URL: server.URL + "?q=test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.InjectionPoints) != 1 {
		t.Fatalf("one point per parameter expected, got %+v", got.InjectionPoints)
	}
	counts := make(map[xctx.ContextType]int)
	quotes := make(map[string]bool)
	for _, c := range got.InjectionPoints[0].Contexts {
		counts[c.Type]++
		quotes[c.QuoteChar] = true
	}
	if counts[xctx.ContextJSString] != 2 || counts[xctx.ContextJSBlock] != 1 || counts[xctx.ContextJSRegexp] != 1 || !quotes["'"] || !quotes[`"`] {
		t.Fatalf("repeated contexts lost: %+v", got.InjectionPoints[0].Contexts)
	}
}
