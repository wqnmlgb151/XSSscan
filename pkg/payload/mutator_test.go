package payload

import (
	"strings"
	"testing"

	ctx "github.com/xsscan/xsscan/pkg/context"
)

func TestMutatorEntityAngleBrackets(t *testing.T) {
	m := NewMutator()
	payload := `<script>alert(1)</script>`
	mutations := m.Mutate(payload, ctx.ContextHTMLBody, 0)

	found := false
	for _, mut := range mutations {
		if mut.Type == MutationEntityAngleBrackets {
			found = true
			if !strings.Contains(mut.Value, "&#60;") {
				t.Error("Entity encoding should replace < with &#60;")
			}
			if !strings.Contains(mut.Value, "&#62;") {
				t.Error("Entity encoding should replace > with &#62;")
			}
			break
		}
	}
	if !found {
		t.Error("Missing entity_angle_brackets mutation")
	}
}

func TestMutatorCaseMix(t *testing.T) {
	m := NewMutator()
	payload := `<script>alert(1)</script>`
	mutations := m.Mutate(payload, ctx.ContextHTMLBody, 0)

	found := false
	for _, mut := range mutations {
		if mut.Type == MutationCaseMix {
			found = true
			if mut.Value == payload {
				t.Error("Case-mixed value should differ from original")
			}
			break
		}
	}
	if !found {
		t.Error("Missing case mix mutation")
	}
}

func TestMutatorEntityPreservesContent(t *testing.T) {
	m := NewMutator()
	payload := `<img src=x onerror=alert(1)>`
	mutations := m.Mutate(payload, ctx.ContextHTMLBody, 0)

	for _, mut := range mutations {
		if mut.Type == MutationEntityAngleBrackets {
			// Non-angle-bracket content should be preserved
			if !strings.Contains(mut.Value, "onerror=alert(1)") {
				t.Errorf("Entity encoding should preserve non-bracket content, got: %s", mut.Value)
			}
			return
		}
	}
	t.Error("Missing entity_angle_brackets mutation")
}

func TestMutatorMaxVariants(t *testing.T) {
	m := NewMutator()
	payload := `<script>alert(1)</script>`
	mutations := m.Mutate(payload, ctx.ContextHTMLBody, 2)

	if len(mutations) != 2 {
		t.Errorf("Expected 2 mutations, got %d", len(mutations))
	}
}

func TestMutatorNoLetters(t *testing.T) {
	m := NewMutator()
	payload := `12345!@#$%`
	mutations := m.Mutate(payload, ctx.ContextHTMLBody, 0)

	// Should not have case_mix for non-letter payloads
	for _, mut := range mutations {
		if mut.Type == MutationCaseMix {
			t.Error("Should not generate case_mix for non-letter payload")
		}
	}
}

func TestMutatorContextAwareJSOnly(t *testing.T) {
	m := NewMutator()
	payload := `';alert(1)//`
	// In JSString context, entity_angle_brackets should NOT be generated
	// because HTML entities are not decoded in JS contexts.
	mutations := m.Mutate(payload, ctx.ContextJSString, 0)

	for _, mut := range mutations {
		if mut.Type == MutationEntityAngleBrackets {
			t.Error("Should not generate entity_angle_brackets for JS context")
		}
		if mut.Type == MutationSpaceToSlash {
			t.Error("Should not generate space_to_slash for JS context")
		}
	}

	// backtick_fn and string_concat SHOULD be generated for JS context
	foundBacktick := false
	foundConcat := false
	for _, mut := range mutations {
		if mut.Type == MutationBacktickFn {
			foundBacktick = true
		}
		if mut.Type == MutationStringConcat {
			foundConcat = true
		}
	}
	if !foundBacktick {
		t.Error("Expected backtick_fn mutation for JS context")
	}
	if !foundConcat {
		t.Error("Expected string_concat mutation for JS context")
	}
}

func TestMutateTargeted_KnownWAF(t *testing.T) {
	m := NewMutator()
	payload := `<img src=x onerror=alert(1)>`

	// Cloudflare-targeted mutations should be a subset of all mutations
	all := m.Mutate(payload, ctx.ContextHTMLBody, 0)
	targeted := m.MutateTargeted(payload, ctx.ContextHTMLBody, "Cloudflare", 0)

	if len(targeted) >= len(all) {
		t.Errorf("Targeted should be subset: got %d, all is %d", len(targeted), len(all))
	}
	if len(targeted) == 0 {
		t.Error("Expected non-empty targeted mutations for Cloudflare")
	}

	// All targeted mutations should be in the full set
	allTypes := make(map[MutationType]bool)
	for _, m := range all {
		allTypes[m.Type] = true
	}
	for _, m := range targeted {
		if !allTypes[m.Type] {
			t.Errorf("Targeted mutation %s not in full set", m.Type)
		}
	}
}

func TestMutateTargeted_UnknownWAF(t *testing.T) {
	m := NewMutator()
	payload := `<img src=x onerror=alert(1)>`

	// Unknown WAF should fall back to all mutations
	targeted := m.MutateTargeted(payload, ctx.ContextHTMLBody, "NonExistentWAF", 0)
	all := m.Mutate(payload, ctx.ContextHTMLBody, 0)

	if len(targeted) != len(all) {
		t.Errorf("Unknown WAF should return all mutations: got %d, want %d", len(targeted), len(all))
	}
}

func TestMutateTargeted_EmptyWAF(t *testing.T) {
	m := NewMutator()
	payload := `<img src=x onerror=alert(1)>`

	// Empty WAF name should fall back to all mutations
	targeted := m.MutateTargeted(payload, ctx.ContextHTMLBody, "", 0)
	all := m.Mutate(payload, ctx.ContextHTMLBody, 0)

	if len(targeted) != len(all) {
		t.Errorf("Empty WAF should return all mutations: got %d, want %d", len(targeted), len(all))
	}
}

func TestMutateTargeted_MaxVariants(t *testing.T) {
	m := NewMutator()
	payload := `<img src=x onerror=alert(1)>`

	targeted := m.MutateTargeted(payload, ctx.ContextHTMLBody, "Cloudflare", 3)
	if len(targeted) != 3 {
		t.Errorf("Expected max 3 mutations, got %d", len(targeted))
	}
}

func TestMutateTargeted_PerWAFStrategies(t *testing.T) {
	m := NewMutator()
	payload := `<img src=x onerror=alert(1)>`

	// Each known WAF should produce different targeted mutations
	wafs := []string{"Cloudflare", "AWS WAF", "Akamai", "ModSecurity", "F5 BIG-IP", "Imperva", "Sucuri", "Wordfence"}
	for _, waf := range wafs {
		t.Run(waf, func(t *testing.T) {
			targeted := m.MutateTargeted(payload, ctx.ContextHTMLBody, waf, 0)
			if len(targeted) == 0 {
				t.Errorf("Expected mutations for %s, got none", waf)
			}
		})
	}
}

func TestMutatorContextAwareHTMLOnly(t *testing.T) {
	m := NewMutator()
	payload := `<img src=x onerror=alert(1)>`
	// In HTMLBody context, JS-only mutations should NOT be generated.
	mutations := m.Mutate(payload, ctx.ContextHTMLBody, 0)

	for _, mut := range mutations {
		if mut.Type == MutationBacktickFn {
			t.Error("Should not generate backtick_fn for HTML context")
		}
		if mut.Type == MutationStringConcat {
			t.Error("Should not generate string_concat for HTML context")
		}
	}

	// HTML-specific mutations SHOULD be generated
	foundEntity := false
	foundTab := false
	for _, mut := range mutations {
		if mut.Type == MutationEntityAngleBrackets {
			foundEntity = true
		}
		if mut.Type == MutationTabInjection {
			foundTab = true
		}
	}
	if !foundEntity {
		t.Error("Expected entity_angle_brackets mutation for HTML context")
	}
	if !foundTab {
		t.Error("Expected tab_injection mutation for HTML context")
	}
}

func TestMutateTargeted_EncodingMutationSelected(t *testing.T) {
	p := `<img src=x onerror=alert(1)>`
	tests := []struct {
		waf      string
		expected MutationType
	}{
		{"Cloudflare", MutationDoubleURLEncode},
		{"AWS WAF", MutationHexEntityMixed},
		{"ModSecurity", MutationHTMLEntityNested},
	}
	for _, tt := range tests {
		mutations := NewMutator().MutateTargeted(p, ctx.ContextHTMLBody, tt.waf, 20)
		found := false
		for _, m := range mutations {
			if m.Type == tt.expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("MutateTargeted(%s) missing expected mutation %s; got %v", tt.waf, tt.expected, mutationTypes(mutations))
		}
	}
}

func mutationTypes(ms []Mutation) []MutationType {
	out := make([]MutationType, len(ms))
	for i, m := range ms {
		out[i] = m.Type
	}
	return out
}
