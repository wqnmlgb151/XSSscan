package scanner

import (
	"net/http"
	"sync"
	"testing"
)

// --- applyCSRFToken ---

func TestApplyCSRFToken_NoToken(t *testing.T) {
	e := &Engine{}
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	e.applyCSRFToken(req)

	// No token set → no header added
	if req.Header.Get("X-CSRF-Token") != "" {
		t.Errorf("Expected no CSRF header, got %s", req.Header.Get("X-CSRF-Token"))
	}
}

func TestApplyCSRFToken_WithDefaultHeader(t *testing.T) {
	e := &Engine{}
	e.csrfToken.Store("my-csrf-token")
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	e.applyCSRFToken(req)

	got := req.Header.Get("X-CSRF-Token")
	if got != "my-csrf-token" {
		t.Errorf("Expected 'my-csrf-token', got %q", got)
	}
}

func TestApplyCSRFToken_WithCustomHeader(t *testing.T) {
	e := &Engine{}
	e.csrfToken.Store("my-csrf-token")
	e.csrfFieldName.Store("X-XSRF-TOKEN")
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	e.applyCSRFToken(req)

	got := req.Header.Get("X-XSRF-TOKEN")
	if got != "my-csrf-token" {
		t.Errorf("Expected 'my-csrf-token' in X-XSRF-TOKEN, got %q", got)
	}
	// Default header should NOT be set
	if req.Header.Get("X-CSRF-Token") != "" {
		t.Errorf("Default X-CSRF-Token should not be set when custom field is used")
	}
}

func TestApplyCSRFToken_OverridesExisting(t *testing.T) {
	e := &Engine{}
	e.csrfToken.Store("new-token")
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-CSRF-Token", "old-token")

	e.applyCSRFToken(req)

	got := req.Header.Get("X-CSRF-Token")
	if got != "new-token" {
		t.Errorf("Expected token to be overridden to 'new-token', got %q", got)
	}
}

// --- atomic CSRF token concurrent access ---

func TestCSRFToken_ConcurrentStoreLoad(t *testing.T) {
	e := &Engine{}
	e.csrfToken.Store("initial")

	var wg sync.WaitGroup
	// Concurrent reads and stores — should not race
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			e.csrfToken.Store("token-" + string(rune('A'+i%26)))
		}(i)
		go func() {
			defer wg.Done()
			_ = e.csrfToken.Load()
		}()
	}
	wg.Wait()

	// Final load should not panic
	_ = e.csrfToken.Load()
}

func TestCSRFToken_LoadEmpty(t *testing.T) {
	e := &Engine{}
	// Never stored — Load returns nil
	val := e.csrfToken.Load()
	if val != nil {
		t.Errorf("Expected nil for uninitialized atomic.Value, got %v", val)
	}
	// Type assertion on nil returns zero value with ok=false
	str, ok := val.(string)
	if ok || str != "" {
		t.Errorf("Expected empty string from nil assertion, got %q (ok=%v)", str, ok)
	}
}

func TestCSRFFieldName_LoadEmpty(t *testing.T) {
	e := &Engine{}
	val := e.csrfFieldName.Load()
	if val != nil {
		t.Errorf("Expected nil for uninitialized atomic.Value, got %v", val)
	}
}
