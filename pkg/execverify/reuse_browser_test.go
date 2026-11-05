package execverify

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func TestVerificationReuseAndAsyncObservation(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}
	allowLocalVerification(t)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<body>"+r.URL.Query().Get("q")+"</body>")
	}))
	defer server.Close()
	v, _ := NewVerifier(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 15*time.Second)
	defer v.Close()
	for _, payload := range []string{`<script>alert(1)</script>`, `<script>setTimeout(()=>alert(1),450)</script>`, `<input onmouseover=alert(1)>`, `<input id=t disabled onfocus=alert(1)><script>setTimeout(()=>document.getElementById("t").disabled=false,500)</script>`, `<input onfocus="if(window.ready)alert(1)"><script>setTimeout(()=>window.ready=true,500)</script>`} {
		result, err := v.VerifyPayload(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "?q=test"}, "q", model.ParamQuery, payload)
		if err != nil || !result.Executed {
			t.Fatalf("execution lost: %s %v %+v", payload, err, result)
		}
	}
	cleanup, cancel := context.WithTimeout(v.browserCtx, time.Second)
	defer cancel()
	ids, _, err := target.GetBrowserContexts().Do(cdp.WithExecutor(cleanup, chromedp.FromContext(v.browserCtx).Browser))
	if err != nil || len(ids) != 0 {
		t.Fatalf("verification contexts leaked: %v %v", ids, err)
	}
}
