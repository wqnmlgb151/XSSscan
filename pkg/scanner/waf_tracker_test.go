package scanner

import (
	"sync"
	"testing"
)

func TestWAFTracker_NoReport(t *testing.T) {
	tr := &WAFTracker{}
	if tr.Detected() {
		t.Error("Expected not detected initially")
	}
	if tr.Result() != nil {
		t.Error("Expected nil result initially")
	}
}

func TestWAFTracker_IgnoreNotDetected(t *testing.T) {
	tr := &WAFTracker{}
	tr.Report(false, "Cloudflare", false)
	if tr.Detected() {
		t.Error("Report with detected=false should not set detected")
	}
}

func TestWAFTracker_SingleReport(t *testing.T) {
	tr := &WAFTracker{}
	tr.Report(true, "Cloudflare", false)
	if !tr.Detected() {
		t.Error("Expected detected after report")
	}
	info := tr.Result()
	if info == nil {
		t.Fatal("Expected non-nil result")
	}
	if info.Name != "Cloudflare" {
		t.Errorf("Expected name Cloudflare, got %q", info.Name)
	}
	if info.Bypassed {
		t.Error("Expected not bypassed")
	}
}

func TestWAFTracker_Bypass(t *testing.T) {
	tr := &WAFTracker{}
	tr.Report(true, "AWS WAF", true)
	info := tr.Result()
	if !info.Bypassed {
		t.Error("Expected bypassed=true")
	}
}

func TestWAFTracker_FirstNameWins(t *testing.T) {
	tr := &WAFTracker{}
	tr.Report(true, "Cloudflare", false)
	tr.Report(true, "AWS WAF", false)
	info := tr.Result()
	if info.Name != "Cloudflare" {
		t.Errorf("Expected first name to win, got %q", info.Name)
	}
}

func TestWAFTracker_EmptyNameDoesNotOverride(t *testing.T) {
	tr := &WAFTracker{}
	tr.Report(true, "Cloudflare", false)
	tr.Report(true, "", false) // subsequent empty name should not overwrite
	info := tr.Result()
	if info.Name != "Cloudflare" {
		t.Errorf("Expected Cloudflare, got %q", info.Name)
	}
}

func TestWAFTracker_Result(t *testing.T) {
	tr := &WAFTracker{}
	tr.Report(true, "ModSecurity", true)
	m := tr.Result()
	if m == nil {
		t.Fatal("Expected non-nil model")
	}
	if m.Name != "ModSecurity" {
		t.Errorf("Expected ModSecurity, got %q", m.Name)
	}
	if !m.Bypassed {
		t.Error("Expected bypassed=true")
	}
}

func TestWAFTracker_ResultNil(t *testing.T) {
	tr := &WAFTracker{}
	if tr.Result() != nil {
		t.Error("Expected nil result when no WAF detected")
	}
}

func TestWAFTracker_ConcurrentReports(t *testing.T) {
	tr := &WAFTracker{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Report(true, "Cloudflare", true)
		}()
	}
	wg.Wait()
	if !tr.Detected() {
		t.Error("Expected detected after concurrent reports")
	}
	info := tr.Result()
	if info.Name != "Cloudflare" {
		t.Errorf("Expected Cloudflare, got %q", info.Name)
	}
	if !info.Bypassed {
		t.Error("Expected bypassed after concurrent reports")
	}
}
