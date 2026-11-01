package dom

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestBatchCookiesRetainTargetOverrideAndHTTPOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var authenticated atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "new" {
			http.Error(w, "wrong cookie precedence", 401)
			return
		}
		authenticated.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body><script>if(!document.cookie.includes('session='))document.body.innerHTML=location.hash</script></body>`)
	}))
	defer server.Close()
	scanner, _ := NewScannerWithAuth(context.Background(), 15*time.Second, &AuthState{Cookies: []*http.Cookie{{Name: "session", Value: "old", Path: "/", HttpOnly: true}, {Name: "first", Value: "a"}}})
	defer scanner.Close()
	target := model.Target{URL: server.URL, Cookies: []*http.Cookie{nil, {Name: "session", Value: "new", Path: "/", HttpOnly: true}, {Name: "second", Value: "b"}}}
	u, _ := url.Parse(server.URL)
	probe := buildDOMTests(u, `<img src=x onerror=alert(1)>`, "xsscanCookie123")[0]
	found, err := scanner.runSingleDOMTest(context.Background(), target, probe, "xsscanCookie123", `<img src=x onerror=alert(1)>`)
	if err != nil || len(found) == 0 || authenticated.Load() == 0 {
		t.Fatalf("cookie order/HTTPOnly changed: hits=%d err=%v found=%+v", authenticated.Load(), err, found)
	}
}
