package dom

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestDOMBrowserSourceSetupAndAuthenticatedPOST(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome required")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	marker := "xsscanSourceFixture"
	for _, source := range []string{"localStorage", "sessionStorage", "document-cookie", "postMessage", "referrer"} {
		t.Run(source, func(t *testing.T) {
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookie, err := r.Cookie("session")
				if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer fixture" || err != nil || cookie.Value != "secret" {
					http.Error(w, "missing authentication", 401)
					return
				}
				if err := r.ParseForm(); err != nil || r.PostForm.Get("q") != "original" {
					http.Error(w, "missing body", 400)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				script := ""
				switch source {
				case "localStorage", "sessionStorage":
					script = fmt.Sprintf("document.body.innerHTML=%s.getItem(%q)||''", source, marker)
				case "document-cookie":
					script = "document.body.innerHTML=document.cookie"
				case "referrer":
					script = "document.body.innerHTML=document.referrer"
				case "postMessage":
					script = "addEventListener('message',e=>document.body.innerHTML=e.data)"
				}
				fmt.Fprintf(w, "<html><body>safe<script>%s</script></body></html>", script)
			}))
			defer server.Close()
			s, err := NewScannerWithAuth(context.Background(), 20*time.Second, &AuthState{Cookies: []*http.Cookie{{Name: "session", Value: "secret", HttpOnly: true}}})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			u, _ := url.Parse(server.URL)
			for _, probe := range buildDOMTests(u, "fixture", marker) {
				if probe.Name != source {
					continue
				}
				findings, err := s.runSingleDOMTest(context.Background(), model.Target{URL: server.URL, Method: "POST", Body: "q=original", Headers: map[string]string{"Authorization": "Bearer fixture", "Content-Type": "application/x-www-form-urlencoded"}}, probe, marker, "fixture")
				if err != nil || len(findings) == 0 {
					t.Fatalf("source lost: %+v %v", findings, err)
				}
			}
		})
	}
}
