package execverify

import (
	"github.com/xsscan/xsscan/pkg/model"
	"testing"
)

func TestCapturedReplayPreservesFreshAuth(t *testing.T) {
	e := &model.HTTPExchange{URL: "http://local/a%2Fb", Request: "POST /a%2Fb?q=value HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer fresh\r\nCookie: session=fresh\r\nX-CSRF-Token: fresh\r\nContent-Length: 10\r\n\r\ncsrf=fresh"}
	got, err := capturedTarget(e, model.Target{Body: "csrf=stale", Headers: map[string]string{"X-CSRF-Token": "stale"}})
	if err != nil || got.Body != "csrf=fresh" || got.Headers["X-Csrf-Token"] != "fresh" || got.Headers["Cookie"] != "session=fresh" || got.URL != "http://local/a%2Fb?q=value" {
		t.Fatalf("replay lost state: %+v %v", got, err)
	}
	e.RequestTruncated = true
	if _, err := capturedTarget(e, got); err == nil {
		t.Fatal("truncated request replayed")
	}
}

func TestCapturedCustomHostIsExplicitlyUnsupported(t *testing.T) {
	_, err := capturedTarget(&model.HTTPExchange{URL: "http://local/", Request: "GET / HTTP/1.1\r\nHost: virtual.other\r\n\r\n"}, model.Target{})
	if err == nil {
		t.Fatal("silently replayed a different virtual host")
	}
}
