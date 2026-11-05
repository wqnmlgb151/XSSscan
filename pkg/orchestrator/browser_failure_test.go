package orchestrator

import (
	"context"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestDOMModuleFailsOnceWhenBaselineNavigationBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome integration")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var seedHits, foreignHits atomic.Int64
	other := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits.Add(1) }))
	defer other.Close()
	seed := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seedHits.Add(1)
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer seed.Close()
	runner, err := New(Plan{Types: []Type{DOM}}, DOMModule(seed.Client(), 15*time.Second, false))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), model.Target{URL: seed.URL})
	if err == nil || result.Stats.Status != model.ScanFailed {
		t.Fatalf("lost incomplete status: %+v %v", result, err)
	}
	if seedHits.Load() != 1 || foreignHits.Load() != 0 {
		t.Fatalf("repeated failure or scope leak: seed=%d foreign=%d", seedHits.Load(), foreignHits.Load())
	}
	if result.Stats.PayloadsSent != 0 || len(result.Stats.Issues) != 1 || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("baseline failure fanned out: %+v %v", result, err)
	}
}
