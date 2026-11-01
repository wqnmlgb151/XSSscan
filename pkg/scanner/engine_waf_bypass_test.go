package scanner

import (
	"testing"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/payload"
)

func TestWAFBypass_DisabledByDefault(t *testing.T) {
	engine := &Engine{
		config: Config{WAFBypass: false},
	}

	if engine.mutator.Load() != nil {
		t.Error("Expected mutator to be nil when WAFBypass is false")
	}
}

func TestWAFBypass_EnabledCreatesMutator(t *testing.T) {
	engine := &Engine{
		config: Config{WAFBypass: true},
	}
	// Simulate the initialization logic
	if engine.config.WAFBypass {
		engine.mutator.Store(payload.NewMutator())
	}

	if engine.mutator.Load() == nil {
		t.Error("Expected mutator to be created when WAFBypass is true")
	}
}

func TestWAFBypass_MutationsGenerated(t *testing.T) {
	mutator := payload.NewMutator()
	payload_value := `<img src=x onerror=alert(1)>`

	mutations := mutator.Mutate(payload_value, ctx.ContextHTMLBody, 0) // 0 = all mutations

	if len(mutations) == 0 {
		t.Error("Expected mutations to be generated")
	}
	t.Logf("Generated %d mutations for payload", len(mutations))

	// Verify each mutation has required fields
	for _, m := range mutations {
		if m.Value == "" {
			t.Error("Mutation has empty value")
		}
		if m.Type == "" {
			t.Error("Mutation has empty type")
		}
		if m.Value == payload_value {
			t.Errorf("Mutation type '%s' has same value as original", m.Type)
		}
	}
}

func TestWAFBypass_MutationTypes(t *testing.T) {
	mutator := payload.NewMutator()
	payload_value := `<img src=x onerror=alert(1)>`

	mutations := mutator.Mutate(payload_value, ctx.ContextHTMLBody, 0)

	// Verify expected mutation types are present
	expectedTypes := map[payload.MutationType]bool{
		payload.MutationEntityAngleBrackets: false,
		payload.MutationCaseMix:             false,
		payload.MutationSpaceToSlash:        false,
	}

	for _, m := range mutations {
		if _, ok := expectedTypes[m.Type]; ok {
			expectedTypes[m.Type] = true
		}
	}

	for typ, found := range expectedTypes {
		if !found {
			t.Errorf("Expected mutation type '%s' not found", typ)
		}
	}
}

func TestWAFBypass_MaxVariantsLimit(t *testing.T) {
	mutator := payload.NewMutator()
	payload_value := `<img src=x onerror=alert(1)>`

	// Request only 3 mutations
	mutations := mutator.Mutate(payload_value, ctx.ContextHTMLBody, 3)

	if len(mutations) != 3 {
		t.Errorf("Expected 3 mutations, got %d", len(mutations))
	}
}

func TestWAFBypass_EmptyPayload(t *testing.T) {
	mutator := payload.NewMutator()
	payload_value := ``

	mutations := mutator.Mutate(payload_value, ctx.ContextHTMLBody, 0)

	// Empty payload should not panic
	t.Logf("Generated %d mutations for empty payload", len(mutations))
}

func TestWAFBypass_ShortPayload(t *testing.T) {
	mutator := payload.NewMutator()
	payload_value := `x`

	mutations := mutator.Mutate(payload_value, ctx.ContextHTMLBody, 0)

	// Short payload should not panic
	t.Logf("Generated %d mutations for short payload", len(mutations))
}
