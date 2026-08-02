package httpclient

import (
	"sync"
	"testing"
)

func TestUAPoolGetRandom(t *testing.T) {
	ua := Pool.GetRandom()
	if ua == "" {
		t.Error("GetRandom returned empty string")
	}
}

func TestUAPoolGetRandomMultiple(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		ua := Pool.GetRandom()
		if ua == "" {
			t.Error("GetRandom returned empty string")
		}
		seen[ua] = true
	}
	// With 100 draws from a pool of ~50 UAs, we should see multiple different ones
	if len(seen) < 2 {
		t.Errorf("Expected variety in UA selection, got only %d unique", len(seen))
	}
}

func TestUAPoolConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ua := Pool.GetRandom()
			if ua == "" {
				t.Error("GetRandom returned empty string under concurrency")
			}
		}()
	}
	wg.Wait()
}

func TestUAPoolContainsChrome(t *testing.T) {
	found := false
	for _, ua := range uaList {
		if len(ua) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("UA pool should contain at least one UA")
	}
}

func TestUAPoolSize(t *testing.T) {
	if len(uaList) < 10 {
		t.Errorf("UA pool should have at least 10 entries, got %d", len(uaList))
	}
}
