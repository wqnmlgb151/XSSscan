package scanner

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"io"
	"strings"
)

func TestVerifyFindings_ReplaysOriginalTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("browser integration")
	}
	previous := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = previous }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if r.Header.Get("X-CSRF-Token") != "fresh" {
			http.Error(w, "stale CSRF header", 400)
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
				p := "<script>alert(1)</script>"
				engine.csrfToken.Store("fresh")
				request, err := engine.buildRequest(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
				if request.Header.Get("X-CSRF-Token") != "fresh" {
					t.Fatal("fresh CSRF not applied")
				}
				exchange := model.HTTPExchange{URL: target.URL, Request: "POST /save HTTP/1.1\r\nHost: " + request.URL.Host + "\r\nAuthorization: Bearer proof\r\nX-CSRF-Token: fresh\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nq=old&csrf=keep"}
				// The CLI target has no fresh header. Only the captured exchange
				// can make the subsequent Chrome POST pass the server's assertion.
				findings[i] = model.Finding{URL: target.URL, Parameter: "q", ParamType: model.ParamBody, Payload: p, Confidence: 0.9, Evidence: model.Evidence{HTTP: &exchange}}
			}
			got := engine.verifyFindingsWithAuth(context.Background(), findings, nil, target)
			for i, finding := range got {
				if !finding.ExecutionVerified || finding.Confidence != 1.0 {
					t.Fatalf("finding %d not verified: %+v; issues=%+v", i, finding, engine.runIssues)
				}
			}
		})
	}
}

func TestVerifyFinding_ReplaysInitialPostRedirect(t *testing.T) {
	if testing.Short() {
		t.Skip("browser integration")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var stored string
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/save" {
			if r.Method != "POST" || r.Header.Get("X-CSRF-Token") != "fresh" {
				http.Error(w, "wrong replay", 400)
				return
			}
			r.ParseForm()
			stored = r.FormValue("q")
			http.Redirect(w, r, "/result", 302)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>"+stored+"</body></html>")
	}))
	defer server.Close()
	p := "<script>alert(1)</script>"
	req, _ := http.NewRequest("POST", server.URL+"/save", strings.NewReader("q="+p))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", "fresh")
	resp, err := httpclient.WithCapture(httpclient.NewClient(0, nil)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	exchange := httpclient.Captured(resp)
	if !strings.HasPrefix(exchange.InitialRequest, "POST /save") || !strings.HasPrefix(exchange.Request, "GET /result") {
		t.Fatalf("lost redirect chain: %+v", exchange)
	}
	engine := makeTestEngine()
	engine.config.VerifyTimeout = 20 * time.Second
	findings := []model.Finding{{URL: server.URL + "/save", Parameter: "q", ParamType: model.ParamBody, Payload: p, Confidence: .9, Evidence: model.Evidence{HTTP: &exchange}}}
	got := engine.verifyFindingsWithAuth(context.Background(), findings, nil, model.Target{URL: server.URL + "/save", Method: "POST", Body: "q=stale"})
	if !got[0].ExecutionVerified {
		t.Fatalf("POST redirect not replayed: %+v", engine.runIssues)
	}
}
