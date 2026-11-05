package chromedp

import (
	"context"
	"errors"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	ext "github.com/chromedp/chromedp"
	"github.com/wqnmlgb151/XSSscan/pkg/requestbudget"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserBudgetNetworkAndCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var hits atomic.Int64
	var active atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/slow":
			active.Add(1)
			defer active.Add(-1)
			<-r.Context().Done()
		case "/start":
			http.Redirect(w, r, "/page", 302)
		case "/page":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><link rel="icon" href="data:,"><script src="/script"></script><link rel="stylesheet" href="/style"></head><body>ok</body></html>`))
		case "/script":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`window.done=false;fetch('/background').then(()=>window.done=true)`))
		case "/concurrent":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><link rel="icon" href="data:,"><body>ok</body></html>`))
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer server.Close()
	alloc, closeAlloc := NewExecAllocator(context.Background(), StandardHeadlessOptions...)
	defer closeAlloc()
	parent, closeParent, _ := NewTabContext(alloc)
	defer closeParent()
	if err := ext.Run(parent); err != nil {
		t.Fatal(err)
	}
	executor := cdp.WithExecutor(parent, ext.FromContext(parent).Browser)
	before, _, err := target.GetBrowserContexts().Do(executor)
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{0, 2} {
		t.Run(map[int64]string{0: "exact", 2: "exhausted"}[limit], func(t *testing.T) {
			hits.Store(0)
			m := requestbudget.New(1, limit)
			caller := requestbudget.WithMeter(context.Background(), m)
			tab, closeTab, _, err := NewIsolatedTabContext(caller, parent, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(tab, 10*time.Second)
			guard, policy := GuardRequests(server.URL, cancel, nil)
			err = ext.Run(ctx, policy, ext.Navigate(server.URL+"/start"), ext.Poll(`window.done===true`, nil))
			guard.Close()
			cancel()
			closeTab()
			closeTab()
			if limit == 0 {
				if err != nil || guard.Err() != nil || hits.Load() != 5 || m.Browser.Count() != 5 {
					t.Fatalf("count mismatch hits=%d count=%d err=%v guard=%v", hits.Load(), m.Browser.Count(), err, guard.Err())
				}
			} else if !errors.Is(guard.Err(), requestbudget.ErrBrowser) || m.Browser.Count() != limit || hits.Load() > limit {
				t.Fatalf("budget overrun hits=%d count=%d err=%v", hits.Load(), m.Browser.Count(), guard.Err())
			}
			if m.HTTP.Count() != 0 {
				t.Fatal("double counted HTTP")
			}
		})
	}
	after, _, err := target.GetBrowserContexts().Do(executor)
	if err != nil || len(before) != len(after) {
		t.Fatalf("contexts leaked %v %v %v", before, after, err)
	}
	m := requestbudget.New(0, 2)
	hits.Store(0)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			caller := requestbudget.WithMeter(context.Background(), m)
			tab, closeTab, _, err := NewIsolatedTabContext(caller, parent, 10*time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			defer closeTab()
			ctx, cancel := context.WithTimeout(tab, 10*time.Second)
			defer cancel()
			g, p := GuardRequests(server.URL, cancel, nil)
			defer g.Close()
			_ = ext.Run(ctx, p, ext.Navigate(server.URL+"/concurrent"))
		})
	}
	wg.Wait()
	if m.Browser.Count() != 2 || hits.Load() != 2 || m.Browser.Denied() == 0 {
		t.Fatalf("concurrent cap count=%d hits=%d denied=%d", m.Browser.Count(), hits.Load(), m.Browser.Denied())
	}
	caller, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := NewIsolatedTabContext(caller, parent, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	after, _, err = target.GetBrowserContexts().Do(executor)
	if err != nil || len(before) != len(after) {
		t.Fatal("concurrent contexts leaked", err)
	}
	t.Run("timeout", func(t *testing.T) {
		m := requestbudget.New(0, 10)
		tab, closeTab, _, err := NewIsolatedTabContext(requestbudget.WithMeter(context.Background(), m), parent, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(tab, 200*time.Millisecond)
		g, p := GuardRequests(server.URL, cancel, nil)
		err = ext.Run(ctx, p, ext.Navigate(server.URL+"/slow"))
		g.Close()
		cancel()
		closeTab()
		if err == nil || m.Browser.Count() != 1 {
			t.Fatalf("timeout accounting: %v count=%d", err, m.Browser.Count())
		}
		deadline := time.Now().Add(2 * time.Second)
		for active.Load() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if active.Load() != 0 {
			t.Fatal("request connection remained active")
		}
	})
}
