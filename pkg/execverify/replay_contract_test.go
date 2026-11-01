package execverify

import (
	"context"
	"github.com/xsscan/xsscan/test/testenv"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
)

func TestCapturedReplayCookieLinesReachLocalServer(t *testing.T) {
	allowLocalVerification(t)
	seen := make(chan string, 1)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, a := r.Cookie("session")
		csrf, b := r.Cookie("csrf")
		body, err := io.ReadAll(r.Body)
		if a != nil || b != nil || err != nil || session.Value != "fresh" || csrf.Value != "fresh" || r.Method != "POST" || string(body) != "q=hello" || r.URL.EscapedPath() != "/a%2Fb" {
			seen <- "request identity/body/cookies changed"
			return
		}
		seen <- "ok"
	}))
	defer server.Close()
	modelURL := server.URL + "/a%2Fb?q=value"
	host := strings.TrimPrefix(server.URL, "http://")
	exchange := &model.HTTPExchange{URL: modelURL, Request: "POST /a%2Fb?q=value HTTP/1.1\r\nHost: " + host + "\r\nCookie: session=fresh\r\nCookie: csrf=fresh\r\nContent-Length: 7\r\n\r\nq=hello"}
	target, err := capturedTarget(exchange, model.Target{})
	if err != nil {
		t.Fatal(err)
	}
	req, err := buildVerificationRequest(context.Background(), target, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := <-seen; got != "ok" {
		t.Fatal(got)
	}
}

func TestCapturedReplayRejectsNonOriginRequestTargets(t *testing.T) {
	for _, line := range []string{"GET http://local/path HTTP/1.1", "CONNECT local:443 HTTP/1.1", "OPTIONS * HTTP/1.1"} {
		_, err := capturedTarget(&model.HTTPExchange{URL: "http://local/", Request: line + "\r\nHost: local\r\n\r\n"}, model.Target{})
		if err == nil {
			t.Fatalf("unsupported request target silently reinterpreted: %s", line)
		}
	}
}

func TestCapturedReplayInitialTruncationTakesPrecedence(t *testing.T) {
	for _, initialTruncated := range []bool{true, false} {
		exchange := &model.HTTPExchange{
			URL: "http://local/final", Request: "GET /final HTTP/1.1\r\nHost: local\r\n\r\n", RequestTruncated: !initialTruncated,
			InitialURL: "http://local/start", InitialRequest: "GET /start HTTP/1.1\r\nHost: local\r\n\r\n", InitialRequestTruncated: initialTruncated,
		}
		got, err := capturedTarget(exchange, model.Target{})
		if initialTruncated {
			if err == nil {
				t.Fatal("used a complete final request to hide a truncated submission")
			}
		} else if err != nil || got.URL != "http://local/start" {
			t.Fatalf("complete initial request not retained: %+v %v", got, err)
		}
	}
}

func TestCapturedReplayRejectsInconsistentFraming(t *testing.T) {
	for _, tc := range []struct{ name, headers, body string }{
		{"short", "Content-Length: 8\r\n", "short"},
		{"extra", "Content-Length: 0\r\n", "extra"},
		{"chunked", "Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := capturedTarget(&model.HTTPExchange{URL: "http://local/", Request: "POST / HTTP/1.1\r\nHost: local\r\n" + tc.headers + "\r\n" + tc.body}, model.Target{})
			if err == nil {
				t.Fatal("silently replayed an incomplete or unsupported body representation")
			}
		})
	}
}

func TestCapturedReplayUsesInitialOnlyAndRetainsEmptyQuery(t *testing.T) {
	target, err := capturedTarget(&model.HTTPExchange{InitialURL: "http://local/original?", InitialRequest: "GET /original? HTTP/1.1\r\nHost: local\r\n\r\n"}, model.Target{URL: "http://stale/"})
	if err != nil || target.URL != "http://local/original?" {
		t.Fatalf("lost initial request or empty query: %+v %v", target, err)
	}
}

func TestCapturedReplayFallbackOwnsMutableState(t *testing.T) {
	input := model.Target{Headers: map[string]string{"Authorization": "fresh"}, Cookies: []*http.Cookie{{Name: "session", Value: "fresh"}}}
	got, err := capturedTarget(nil, input)
	if err != nil {
		t.Fatal(err)
	}
	got.Headers["Authorization"] = "other"
	got.Cookies[0].Value = "other"
	if input.Headers["Authorization"] != "fresh" || input.Cookies[0].Value != "fresh" {
		t.Fatal("fallback shared mutable credentials")
	}
}

func TestVerifierAuthSnapshotDoesNotFollowCallerMutations(t *testing.T) {
	input := &AuthState{Cookies: []*http.Cookie{{Name: "session", Value: "original", Unparsed: []string{"original"}}, nil}}
	v, err := NewVerifierWithAuth(context.Background(), time.Second, input)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	input.Cookies[0].Value = "other"
	input.Cookies[0].Unparsed[0] = "other"
	input.Cookies[1] = &http.Cookie{Name: "extra", Value: "other"}
	if v.auth.Cookies[0].Value != "original" || v.auth.Cookies[0].Unparsed[0] != "original" || v.auth.Cookies[1] != nil {
		t.Fatal("verifier identity changed with caller-owned cookies")
	}
}
