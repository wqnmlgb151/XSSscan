package chromedp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/target"
	ext "github.com/chromedp/chromedp"
)

func TestGuardQueueSaturationCancelsWithoutBlocking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := &RequestGuard{pending: make(chan *fetch.EventRequestPaused, 2)}
	for range 3 {
		g.enqueue(&fetch.EventRequestPaused{}, cancel)
	}
	if ctx.Err() == nil || g.Err() == nil || !strings.Contains(g.Err().Error(), "capacity exceeded") {
		t.Fatalf("saturation lost: %v %v", ctx.Err(), g.Err())
	}
}

func TestCleanupDiagnosticsAreSeparateFromProtocolEvidence(t *testing.T) {
	d := &Diagnostics{}
	d.cleanupError(errors.New("dispose failed"))
	if d.Err() != nil || !OnlyCleanupErrors(d.CleanupErr()) {
		t.Fatalf("cleanup poisoned protocol evidence: %v %v", d.Err(), d.CleanupErr())
	}
	if OnlyCleanupErrors(errors.Join(d.CleanupErr(), errors.New("protocol failed"))) {
		t.Fatal("mixed failures treated as cleanup only")
	}
}

func TestIsolatedLifetimeFollowsCallerAndDisposesExactlyOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome integration")
	}
	alloc, closeAlloc := NewExecAllocator(context.Background(), StandardHeadlessOptions...)
	defer closeAlloc()
	parent, closeParent, _ := NewTabContext(alloc)
	defer closeParent()
	if err := ext.Run(parent); err != nil {
		t.Fatal(err)
	}
	owner := ext.FromContext(parent)
	executor := cdp.WithExecutor(parent, owner.Browser)
	before, _, err := target.GetBrowserContexts().Do(executor)
	if err != nil {
		t.Fatal(err)
	}
	caller, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()
	tab, closeTab, diagnostics, err := NewIsolatedTabContext(caller, parent, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTab()
	if err := ext.Run(tab); err != nil {
		t.Fatal(err)
	}
	cancelCaller()
	select {
	case <-tab.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("caller cancellation did not reach tab")
	}
	closeTab()
	closeTab()
	if err := diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	after, _, err := target.GetBrowserContexts().Do(executor)
	if err != nil || len(after) != len(before) || parent.Err() != nil {
		t.Fatalf("context leaked or parent canceled: %v %v %v", before, after, err)
	}
}
