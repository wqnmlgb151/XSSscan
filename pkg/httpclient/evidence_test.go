package httpclient

import (
	"context"
	"encoding/base64"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCaptureBinaryAndIncomplete(t *testing.T) {
	c := &Capture{responseHead: "HTTP/1.1 200 OK\r\n\r\n", responseBody: []byte{0, 1, 255}}
	got := c.Snapshot()
	decoded, err := base64.StdEncoding.DecodeString(got.ResponseBase64)
	if err != nil || string(decoded) != got.Response || !got.ResponseIncomplete {
		t.Fatalf("binary evidence lost: %+v %v", got, err)
	}
}

func TestCapturedActualCookiesCredentialsBodyAndEncodedPath(t *testing.T) {

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "q=payload&csrf=fresh" || r.Header.Get("Authorization") != "Bearer original" {
			t.Error("request changed")
		}
		if c, e := r.Cookie("session"); e != nil || c.Value != "jar-secret" {
			t.Error("cookie missing")
		}
		w.Header().Add("Set-Cookie", "one=secret")
		w.Header().Add("Set-Cookie", "two=secret")
		w.Write([]byte("<body>original</body>"))
	}))
	defer server.Close()
	client := WithCapture(NewClient(0, nil, ssrfguard.Policy{AllowPrivate: true}))
	u, _ := url.Parse(server.URL)
	client.Jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "jar-secret"}})
	req, _ := http.NewRequest("POST", server.URL+"/a%2Fb?q=original", strings.NewReader("q=payload&csrf=fresh"))
	req.Header.Set("Authorization", "Bearer original")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	exchange := Captured(resp)
	for _, value := range []string{"POST /a%2Fb?q=original HTTP/1.1", "Authorization: Bearer original", "Cookie: session=jar-secret", "q=payload&csrf=fresh"} {
		if !strings.Contains(exchange.Request, value) {
			t.Fatalf("missing actual evidence %q: %+v", value, exchange)
		}
	}
	if !strings.Contains(exchange.Response, "HTTP/1.1 200 OK\r\n") || !strings.Contains(exchange.Response, "Set-Cookie: two=secret") || exchange.ResponseIncomplete {
		t.Fatalf("bad response: %+v", exchange)
	}

}

func TestCaptureLimitsDoNotTruncateConsumer(t *testing.T) {

	large := strings.Repeat("x", MaxEvidenceBody+31)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, large) }))
	defer server.Close()
	ctx, capture := RecordContext(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	req, _ := http.NewRequestWithContext(ctx, "POST", server.URL, strings.NewReader(large))
	resp, err := WithCapture(NewClient(0, nil, ssrfguard.Policy{AllowPrivate: true})).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	exchange := capture.Snapshot()
	if err != nil || string(body) != large || !exchange.RequestTruncated || !exchange.ResponseTruncated || exchange.ResponseIncomplete {
		t.Fatalf("capture altered response or limits: %v %+v", err, exchange)
	}
}
