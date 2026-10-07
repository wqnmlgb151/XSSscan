package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestVerifyFindings_ReplaysOriginalTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("browser integration")
	}
	previous := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = previous }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/save" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer proof" {
			http.Error(w, "lost original request", 400)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.FormValue("csrf") != "keep" {
			http.Error(w, "lost CSRF field", 400)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>"+r.FormValue("q")+"</body></html>")
	}))
	defer server.Close()
	target := model.Target{URL: server.URL + "/save", Method: "POST", Body: "q=old&csrf=keep", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Bearer proof"}}
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			engine := makeTestEngine()
			engine.config.VerifyTimeout = 20 * time.Second
			findings := make([]model.Finding, count)
			for i := range findings {
				findings[i] = model.Finding{URL: target.URL, Parameter: "q", ParamType: model.ParamBody, Payload: fmt.Sprintf("<script>alert(%d)</script>", i), Confidence: 0.9}
			}
			got := engine.verifyFindingsWithAuth(context.Background(), findings, nil, target)
			for i, finding := range got {
				if !finding.ExecutionVerified || finding.Confidence != 1.0 {
					t.Fatalf("finding %d not verified: %+v", i, finding)
				}
			}
		})
	}
}
