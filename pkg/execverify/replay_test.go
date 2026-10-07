package execverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func allowLocalVerification(t *testing.T) {
	t.Helper()
	previous := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	t.Cleanup(func() { ssrfguard.AllowPrivate = previous })
}

func TestBuildVerificationRequest_PreservesOriginal(t *testing.T) {
	for _, ct := range []string{"application/x-www-form-urlencoded", "application/json"} {
		t.Run(ct, func(t *testing.T) {
			body := "q=old&csrf=token"
			if ct == "application/json" {
				body = `{"q":"old","csrf":"token"}`
			}
			target := model.Target{URL: "https://example.com/save", Method: "POST", Body: body,
				Headers: map[string]string{"Content-Type": ct, "Authorization": "Bearer token"},
				Cookies: []*http.Cookie{{Name: "session", Value: "secret"}}}
			req, err := buildVerificationRequest(context.Background(), target, "q", model.ParamBody, "injected")
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(req.Body)
			if req.Method != "POST" || req.Header.Get("Authorization") != "Bearer token" || req.Header.Get("Content-Type") != ct || !strings.Contains(string(got), "token") || !strings.Contains(string(got), "injected") {
				t.Fatalf("Request was not preserved: %s %v %s", req.Method, req.Header, got)
			}
			cookie, err := req.Cookie("session")
			if err != nil || cookie.Value != "secret" {
				t.Fatalf("Missing session: %v", err)
			}
			if target.Body != body || target.Cookies[0].Value != "secret" {
				t.Fatal("Original target mutated")
			}
		})
	}
}

func TestBuildVerificationRequest_ReplacesCookieAndHeader(t *testing.T) {
	target := model.Target{URL: "https://example.com/", Headers: map[string]string{"x-test": "old", "Cookie": "q=old; session=keep"}}
	req, err := buildVerificationRequest(context.Background(), target, "X-Test", model.ParamHeader, "new")
	if err != nil || req.Header.Get("X-Test") != "new" {
		t.Fatalf("Header injection failed: %v", err)
	}
	req, err = buildVerificationRequest(context.Background(), target, "q", model.ParamCookie, "new")
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Cookie") != "session=keep; q=new" {
		t.Fatal(req.Header.Get("Cookie"))
	}
	if target.Headers["x-test"] != "old" || target.Headers["Cookie"] != "q=old; session=keep" {
		t.Fatal("Original headers mutated")
	}
}

func TestBuildNavigationURL_PathPosition(t *testing.T) {
	v := &Verifier{}
	for _, tc := range []struct{ path, param, want string }{
		{"/a/b/c", "path[2]", "/a/injected/c"},
		{"/a/a", "path[2]", "/a/injected"},
		{"/api/{id}/profile", "id", "/api/injected/profile"},
		{"/api/:id/profile", "id", "/api/injected/profile"},
		{"/a%2Fb/c", "path[2]", "/a%2Fb/injected"},
	} {
		got, err := v.buildNavigationURL(model.Target{URL: "https://example.com" + tc.path + "?keep=1"}, tc.param, model.ParamPath, "injected")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(got)
		if u.EscapedPath() != tc.want || u.RawQuery != "keep=1" {
			t.Fatalf("%s: %s", tc.param, got)
		}
	}
	for _, name := range []string{"path[0]", "path[-1]", "path[9]", "path[x]", "missing"} {
		if _, err := v.buildNavigationURL(model.Target{URL: "https://example.com/a/b"}, name, model.ParamPath, "x"); err == nil {
			t.Fatalf("Accepted invalid path %q", name)
		}
	}
}

func TestVerifyPayload_ReplaysAuthenticatedPOST(t *testing.T) {
	if testing.Short() {
		t.Skip("browser integration")
	}
	allowLocalVerification(t)
	for _, ct := range []string{"application/x-www-form-urlencoded", "application/json"} {
		t.Run(ct, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/save" {
					http.NotFound(w, r)
					return
				}
				cookie, _ := r.Cookie("session")
				if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer token" || cookie == nil || cookie.Value != "secret" || r.Header.Get("Content-Type") != ct {
					http.Error(w, "bad replay", 400)
					return
				}
				var q, csrf string
				if ct == "application/json" {
					var values map[string]string
					if err := json.NewDecoder(r.Body).Decode(&values); err != nil {
						http.Error(w, err.Error(), 400)
						return
					}
					q, csrf = values["q"], values["csrf"]
				} else {
					r.ParseForm()
					q, csrf = r.FormValue("q"), r.FormValue("csrf")
				}
				if csrf != "token" {
					http.Error(w, "lost csrf", 400)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				io.WriteString(w, "<html><body>"+q+"</body></html>")
			}))
			defer server.Close()
			v, err := NewVerifier(context.Background(), 15*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			body := "q=old&csrf=token"
			if ct == "application/json" {
				body = `{"q":"old","csrf":"token"}`
			}
			target := model.Target{URL: server.URL + "/save", Method: "POST", Body: body, Headers: map[string]string{"Content-Type": ct, "Authorization": "Bearer token"}, Cookies: []*http.Cookie{{Name: "session", Value: "secret"}}}
			result, err := v.VerifyPayload(context.Background(), target, "q", model.ParamBody, `<script>alert('replayed')</script>`)
			if err != nil || !result.Executed || result.DialogMessage != "replayed" {
				t.Fatalf("POST not verified: %+v, %v", result, err)
			}
		})
	}
}

func TestVerifyPayload_DialogVariantsAndInertReflection(t *testing.T) {
	if testing.Short() {
		t.Skip("browser integration")
	}
	allowLocalVerification(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		value := r.URL.Query().Get("q")
		if r.URL.Path == "/inert" {
			fmt.Fprint(w, "<html><body><textarea>"+value+"</textarea></body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>"+value+"</body></html>")
	}))
	defer server.Close()
	v, err := NewVerifier(context.Background(), 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, tc := range []struct{ path, value, dialog string }{
		{"/", `<script>confirm('proof')</script>`, "confirm"},
		{"/", `<script>setTimeout(()=>prompt('proof'),100)</script>`, "prompt"},
		{"/inert", `<script>alert('proof')</script>`, ""},
	} {
		result, err := v.VerifyPayload(context.Background(), model.Target{URL: server.URL + tc.path}, "q", model.ParamQuery, tc.value)
		if err != nil {
			t.Fatal(err)
		}
		if result.Executed != (tc.dialog != "") || result.DialogType != tc.dialog {
			t.Fatalf("%s: %+v", tc.path, result)
		}
	}
}
