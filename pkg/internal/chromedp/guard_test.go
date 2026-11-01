package chromedp

import (
	"context"
	"errors"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/browser"
	ext "github.com/chromedp/chromedp"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestBrowserGuardNavigationDiagnostic(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome integration")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var blockedHits atomic.Int64
	other := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { blockedHits.Add(1) }))
	defer other.Close()
	seed := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/destination", http.StatusFound)
	}))
	defer seed.Close()
	alloc, closeAlloc := NewExecAllocator(context.Background(), StandardHeadlessOptions...)
	defer closeAlloc()
	tab, closeTab, _ := NewTabContext(alloc)
	defer closeTab()
	ctx, cancel := context.WithTimeout(tab, 15*time.Second)
	defer cancel()
	guard, policy := GuardRequests(seed.URL, cancel, nil)
	err := ext.Run(ctx, policy, ext.Navigate(seed.URL))
	var blocked *NavigationPolicyError
	if err == nil || !errors.As(guard.Err(), &blocked) {
		t.Fatalf("lost policy diagnostic: navigation=%v policy=%v", err, guard.Err())
	}
	if blocked.Origin != seed.URL || blocked.RequestURL != other.URL+"/destination" {
		t.Fatalf("wrong attribution: %+v", blocked)
	}
	if blockedHits.Load() != 0 {
		t.Fatal("blocked origin was contacted")
	}
}

func TestBrowserGuardSubframeBlockDoesNotFailMainPage(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome integration")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var blockedHits atomic.Int64
	other := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { blockedHits.Add(1) }))
	defer other.Close()
	seed := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><iframe src="` + other.URL + `"></iframe><p id="ok">ready</p></body></html>`))
	}))
	defer seed.Close()
	alloc, closeAlloc := NewExecAllocator(context.Background(), StandardHeadlessOptions...)
	defer closeAlloc()
	tab, closeTab, _ := NewTabContext(alloc)
	defer closeTab()
	ctx, cancel := context.WithTimeout(tab, 15*time.Second)
	defer cancel()
	guard, policy := GuardRequests(seed.URL, cancel, nil)
	var content string
	if err := ext.Run(ctx, policy, ext.Navigate(seed.URL), ext.Text("#ok", &content), ext.Sleep(200*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if guard.Err() != nil || content != "ready" || blockedHits.Load() != 0 {
		t.Fatalf("main page failed: content=%q policy=%v foreign=%d", content, guard.Err(), blockedHits.Load())
	}
}

func TestBrowserAllocatorPreservesExplicitHTTPScheme(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome integration")
	}
	alloc, closeAlloc := NewExecAllocator(context.Background(), StandardHeadlessOptions...)
	defer closeAlloc()
	tab, closeTab, _ := NewTabContext(alloc)
	defer closeTab()
	ctx, cancel := context.WithTimeout(tab, 15*time.Second)
	defer cancel()
	var arguments []string
	if err := ext.Run(ctx, ext.ActionFunc(func(ctx context.Context) error {
		var err error
		arguments, err = browser.GetBrowserCommandLine().Do(ctx)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	for _, arg := range arguments {
		if strings.HasPrefix(arg, "--disable-features=") {
			for _, feature := range []string{"HttpsUpgrades", "site-per-process", "Translate", "BlinkGenPropertyTrees"} {
				if !strings.Contains(arg, feature) {
					t.Fatalf("missing %s in %s", feature, arg)
				}
			}
			return
		}
	}
	t.Fatal("disabled feature list missing")
}
