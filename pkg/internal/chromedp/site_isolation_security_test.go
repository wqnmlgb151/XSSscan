package chromedp

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	ext "github.com/chromedp/chromedp"
	browserconfig "github.com/wqnmlgb151/XSSscan/pkg/browser"
	"github.com/wqnmlgb151/XSSscan/pkg/requestbudget"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
)

func TestRestoredSiteIsolationSupportsGuardedContexts(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/script" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`window.executionProof=true;`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<link rel=icon href="data:,"><script src="/script"></script><body>ok</body>`))
	}))
	defer server.Close()
	root := ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true})
	options := append(append([]ext.ExecAllocatorOption{}, StandardHeadlessOptions...), ext.Flag("disable-features", "Translate,BlinkGenPropertyTrees,HttpsUpgrades"), ext.Flag("site-per-process", true))
	alloc, finish := NewExecAllocator(root, options...)
	defer finish()
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
	for i := 0; i < 2; i++ {
		meter := requestbudget.New(0, 2)
		caller := requestbudget.WithMeter(root, meter)
		tab, closeTab, _, err := NewIsolatedTabContext(caller, parent, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(tab, 10*time.Second)
		guard, policy := GuardRequests(server.URL, cancel, nil)
		var proof, isolated bool
		err = ext.Run(ctx, policy, ext.Navigate(server.URL), ext.Evaluate(`window.executionProof===true`, &proof), ext.Evaluate(`localStorage.getItem('isolation')===null`, &isolated), ext.Evaluate(`localStorage.setItem('isolation','value')`, nil))
		guard.Close()
		cancel()
		closeTab()
		if err != nil || guard.Err() != nil || !proof || !isolated || meter.Browser.Count() != 2 {
			t.Fatalf("site isolation guard/context regression: proof=%v isolated=%v budget=%d error=%v guard=%v", proof, isolated, meter.Browser.Count(), err, guard.Err())
		}
	}
	after, _, err := target.GetBrowserContexts().Do(executor)
	if err != nil || len(after) != len(before) {
		t.Fatalf("isolated contexts leaked: %v", err)
	}
}

func TestBrowserDefaultKeepsSiteIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	alloc, finish := NewExecAllocator(context.Background(), StandardHeadlessOptions...)
	defer finish()
	tab, closeTab, _ := NewTabContext(alloc)
	defer closeTab()
	var arguments []string
	if err := ext.Run(tab, ext.ActionFunc(func(ctx context.Context) error {
		var err error
		arguments, err = browser.GetBrowserCommandLine().Do(ctx)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	enabled := false
	for _, arg := range arguments {
		if arg == "--site-per-process" {
			enabled = true
		}
		if strings.HasPrefix(arg, "--disable-features=") && strings.Contains(arg, "site-per-process") {
			t.Fatal("site isolation explicitly disabled")
		}
	}
	if !enabled {
		t.Fatal("site-per-process isolation not enabled")
	}
}

func TestLegacySiteIsolationOptOut(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	alloc, finish := NewExecAllocator(browserconfig.WithSiteIsolationDisabled(context.Background(), true), StandardHeadlessOptions...)
	defer finish()
	tab, closeTab, _ := NewTabContext(alloc)
	defer closeTab()
	var arguments []string
	if err := ext.Run(tab, ext.ActionFunc(func(ctx context.Context) error {
		var err error
		arguments, err = browser.GetBrowserCommandLine().Do(ctx)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	restored := false
	for _, arg := range arguments {
		if arg == "--site-per-process" {
			t.Fatal("legacy switch did not remove forced site isolation")
		}
		if strings.HasPrefix(arg, "--disable-features=") && strings.Contains(arg, "site-per-process") {
			restored = true
		}
	}
	if !restored {
		t.Fatal("legacy feature configuration not restored")
	}
}

func TestChromeBackgroundControlsRemainEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	alloc, finish := NewExecAllocator(context.Background(), StandardHeadlessOptions...)
	defer finish()
	tab, closeTab, _ := NewTabContext(alloc)
	defer closeTab()
	var arguments []string
	if err := ext.Run(tab, ext.ActionFunc(func(ctx context.Context) error {
		var err error
		arguments, err = browser.GetBrowserCommandLine().Do(ctx)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"disable-background-networking", "disable-sync", "disable-component-update"} {
		t.Run(flag, func(t *testing.T) {
			for _, arg := range arguments {
				if arg == "--"+flag {
					return
				}
			}
			t.Fatalf("existing browser hardening flag missing: %s", flag)
		})
	}
}

func TestChromeLegacyStartupRestoresPreviousFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	alloc, finish := NewExecAllocator(browserconfig.WithLegacyStartup(context.Background(), true), StandardHeadlessOptions...)
	defer finish()
	tab, closeTab, _ := NewTabContext(alloc)
	defer closeTab()
	var arguments []string
	if err := ext.Run(tab, ext.ActionFunc(func(ctx context.Context) error {
		var err error
		arguments, err = browser.GetBrowserCommandLine().Do(ctx)
		return err
	})); err != nil {
		t.Fatal(err)
	}
	restored := false
	for _, arg := range arguments {
		if arg == "--site-per-process" || arg == "--disable-component-update" {
			t.Fatalf("legacy startup did not restore %s", arg)
		}
		if strings.HasPrefix(arg, "--disable-features=") && strings.Contains(arg, "site-per-process") {
			restored = true
		}
	}
	if !restored {
		t.Fatal("legacy site-isolation flags missing")
	}
}
