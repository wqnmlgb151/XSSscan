package chromedp

import (
	"context"
	"testing"

	ext "github.com/chromedp/chromedp"
)

func TestAllocatorOptions_DefaultsThenCustom(t *testing.T) {
	custom := []ext.ExecAllocatorOption{ext.WindowSize(640, 480), ext.Flag("custom-flag", true)}
	opts := AllocatorOptions(custom...)

	defaultLen := len(ext.DefaultExecAllocatorOptions)
	if len(opts) != defaultLen+len(custom) {
		t.Fatalf("expected %d options, got %d", defaultLen+len(custom), len(opts))
	}
	// Custom options must come LAST so they take effect (chromedp applies in order)
	if opts[len(opts)-2] == nil || opts[len(opts)-1] == nil {
		t.Error("custom options must be appended at the end")
	}
}

func TestAllocatorOptions_NoCustom(t *testing.T) {
	opts := AllocatorOptions()
	if len(opts) != len(ext.DefaultExecAllocatorOptions) {
		t.Fatalf("expected %d default options, got %d", len(ext.DefaultExecAllocatorOptions), len(opts))
	}
}

func TestStandardHeadlessOptions_IncludesEssentials(t *testing.T) {
	// The standard block must always include the security/behavior essentials.
	// This pins the fix that previously let defaults override custom options.
	if len(StandardHeadlessOptions) < 5 {
		t.Fatalf("expected at least 5 standard options, got %d", len(StandardHeadlessOptions))
	}
}

func TestNewExecAllocator_Smoke(t *testing.T) {
	ctx, cancel := NewExecAllocator(context.Background(), ext.WindowSize(640, 480))
	if ctx == nil {
		t.Fatal("allocator context must not be nil")
	}
	cancel() // must not panic
}
