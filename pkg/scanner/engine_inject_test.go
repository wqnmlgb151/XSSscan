package scanner

import (
	"net/http"
	"sync"
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

func TestInjectPayloadDoesNotMutateOriginal(t *testing.T) {
	original := model.Target{
		URL:     "http://example.com/page?q=test",
		Method:  "GET",
		Headers: map[string]string{"X-Custom": "original"},
		Cookies: []*http.Cookie{{Name: "session", Value: "original"}},
	}

	engine := &Engine{}

	// Inject a header param
	param := model.Parameter{Name: "X-Custom", Type: model.ParamHeader}
	_, err := engine.injectPayload(original, param, "PAYLOAD")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	// Original headers must be unchanged
	if original.Headers["X-Custom"] != "original" {
		t.Errorf("Original header was mutated! Got: %s", original.Headers["X-Custom"])
	}
}

func TestConcurrentHeaderInjection(t *testing.T) {
	original := model.Target{
		URL:     "http://example.com/page?q=test",
		Method:  "GET",
		Headers: map[string]string{"X-1": "v1", "X-2": "v2", "X-3": "v3"},
	}
	for _, c := range []*http.Cookie{{Name: "c1", Value: "v1"}, {Name: "c2", Value: "v2"}} {
		original.Cookies = append(original.Cookies, c)
	}

	engine := &Engine{}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			param := model.Parameter{Name: "X-1", Type: model.ParamHeader}
			_, _ = engine.injectPayload(original, param, "PAYLOAD")
		}(i)
	}
	wg.Wait()

	// Original must be unchanged after concurrent access
	if original.Headers["X-1"] != "v1" {
		t.Errorf("X-1 was mutated: %s", original.Headers["X-1"])
	}
	if original.Headers["X-2"] != "v2" {
		t.Errorf("X-2 was mutated: %s", original.Headers["X-2"])
	}
	if original.Headers["X-3"] != "v3" {
		t.Errorf("X-3 was mutated: %s", original.Headers["X-3"])
	}
}

func TestInjectPayloadHeaderIsolation(t *testing.T) {
	original := model.Target{
		URL:     "http://example.com/page?q=test",
		Method:  "GET",
		Headers: map[string]string{"X-Custom": "original", "X-Other": "untouched"},
	}

	engine := &Engine{}
	param := model.Parameter{Name: "X-Custom", Type: model.ParamHeader}
	modified, err := engine.injectPayload(original, param, "PAYLOAD")
	if err != nil {
		t.Fatalf("injectPayload failed: %v", err)
	}

	// Modified should have the payload
	if modified.Headers["X-Custom"] != "PAYLOAD" {
		t.Errorf("Expected modified X-Custom=PAYLOAD, got %s", modified.Headers["X-Custom"])
	}
	// X-Other should be unchanged in modified
	if modified.Headers["X-Other"] != "untouched" {
		t.Errorf("Expected X-Other=untouched, got %s", modified.Headers["X-Other"])
	}
	// Original should be completely unchanged
	if original.Headers["X-Custom"] != "original" {
		t.Errorf("Original was mutated! X-Custom=%s", original.Headers["X-Custom"])
	}
}
