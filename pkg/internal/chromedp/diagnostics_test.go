package chromedp

import (
	"context"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	ext "github.com/chromedp/chromedp"
)

func TestDiagnosticsProtocolFailure(t *testing.T) {
	d := &Diagnostics{}
	d.errorf("%s", "json: cannot unmarshal object into string")
	if d.Err() == nil {
		t.Fatal("decode failure discarded")
	}
}

func TestBrowserProtocolDecoding(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Chrome")
	}
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "test=value; Path=/; SameSite=Lax")
		if r.URL.Path == "/frame" {
			_, _ = w.Write([]byte(`<html><body>frame</body></html>`))
			return
		}
		_, _ = w.Write([]byte(`<html><body><iframe src="/frame"></iframe></body></html>`))
	}))
	defer server.Close()
	alloc, closeAlloc := NewExecAllocator(context.Background(), StandardHeadlessOptions...)
	defer closeAlloc()
	tab, closeTab, diagnostics := NewTabContext(alloc)
	defer closeTab()
	ctx, cancel := context.WithTimeout(tab, 20*time.Second)
	defer cancel()
	if err := ext.Run(ctx, network.Enable(), ext.Navigate(server.URL), ext.WaitReady("body"), ext.Sleep(100*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
}
