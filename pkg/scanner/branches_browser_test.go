package scanner

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"strings"
	"testing"
	"time"

	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/execverify"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/pkg/verify"
)

func TestConstantBranchesAgreeWithBrowser(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/if":
			fmt.Fprint(w, "<script>if(false){"+q+"}</script>")
		case "/and":
			fmt.Fprint(w, "<script>false && "+q+"</script>")
		case "/var":
			fmt.Fprint(w, "<script>if(false){var x="+q+"}</script>")
		default:
			fmt.Fprint(w, "<script>if(true){"+q+"}</script>")
		}
	}))
	defer server.Close()
	v, err := execverify.NewVerifier(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, path := range []string{"/if", "/and", "/var", "/live"} {
		t.Run(path, func(t *testing.T) {
			body := "<script>if(false){alert(1)}</script>"
			if path == "/and" {
				body = "<script>false && alert(1)</script>"
			}
			if path == "/var" {
				body = "<script>if(false){var x=alert(1)}</script>"
			}
			if path == "/live" {
				body = "<script>if(true){alert(1)}</script>"
			}
			assessment := verify.NewVerifier().Verify(body, strings.ToLower(body), payload.Payload{Value: "alert(1)", Context: xctx.ContextJSBlock}, model.InjectionPoint{}, nil, verify.WAFResult{})
			result, err := v.VerifyPayload(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + path + "?q=x"}, "q", model.ParamQuery, "alert(1)")
			if err != nil || result == nil {
				t.Fatalf("browser result=%+v err=%v", result, err)
			}
			want := path == "/live"
			if assessment.Vulnerable != want || result.Executed != want {
				t.Fatalf("want=%v structure=%+v browser=%+v", want, assessment, result)
			}
		})
	}
}
