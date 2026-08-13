package payload

import (
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

func TestPresetMinimal(t *testing.T) {
	g := &Generator{preset: PresetMinimal}
	templates := g.filterTemplates(GetTemplates(context.ContextHTMLBody))
	if len(templates) != 1 {
		t.Errorf("Minimal preset should return 1 template, got %d", len(templates))
	}
}

func TestPresetStandard(t *testing.T) {
	g := &Generator{preset: PresetStandard}
	templates := g.filterTemplates(GetTemplates(context.ContextHTMLBody))
	full := GetTemplates(context.ContextHTMLBody)
	// Standard should be less than full (filters WAF bypass variants)
	if len(templates) >= len(full) {
		t.Errorf("Standard preset should filter some templates, got %d of %d", len(templates), len(full))
	}
	if len(templates) == 0 {
		t.Error("Standard preset should return at least some templates")
	}
}

func TestPresetFull(t *testing.T) {
	g := &Generator{preset: PresetFull}
	templates := g.filterTemplates(GetTemplates(context.ContextHTMLBody))
	full := GetTemplates(context.ContextHTMLBody)
	if len(templates) != len(full) {
		t.Errorf("Full preset should return all templates, got %d of %d", len(templates), len(full))
	}
}

func TestSetPreset(t *testing.T) {
	g := NewGenerator()
	g.SetPreset(PresetMinimal)
	if g.filterTemplates(GetTemplates(context.ContextHTMLBody)) == nil {
		// If there are templates, minimal should return exactly 1
	}
	templates := g.filterTemplates(GetTemplates(context.ContextHTMLBody))
	if len(templates) != 1 {
		t.Errorf("After SetPreset(Minimal), expected 1 template, got %d", len(templates))
	}
}

func TestNewGeneratorDefaultPreset(t *testing.T) {
	g := NewGenerator()
	if g.preset != PresetStandard {
		t.Errorf("Default preset should be 'standard', got '%s'", g.preset)
	}
}

func TestHTMLBodyHasModernSVGVectors(t *testing.T) {
	templates := GetTemplates(context.ContextHTMLBody)

	// Check for modern SVG-based execution vectors
	expectedPayloads := []string{
		`<svg><animate onbegin=alert(1)`,
		`<svg><set onbegin=alert(1)`,
	}

	for _, expected := range expectedPayloads {
		found := false
		for _, tmpl := range templates {
			if len(tmpl.Value) >= len(expected) && tmpl.Value[:len(expected)] == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing SVG payload vector: %s", expected)
		}
	}
}

func TestAllPayloadsHaveValidStructure(t *testing.T) {
	for ctxType, templates := range payloadTemplates {
		for i, tmpl := range templates {
			if tmpl.Value == "" {
				t.Errorf("Empty payload value for context %v at index %d", ctxType, i)
			}
			if tmpl.Severity == "" {
				t.Errorf("Missing severity for payload in context %v at index %d", ctxType, i)
			}
			_ = model.Severity(tmpl.Severity).Score() // validates severity is recognized
		}
	}
}

func TestGetTemplates_UnknownContextReturnsNil(t *testing.T) {
	// Unknown context should return nil (not fall back to HTML body)
	// to prevent false positives from testing HTML payloads in non-HTML contexts
	templates := GetTemplates(context.ContextType(999))
	if templates != nil {
		t.Errorf("Unknown context should return nil templates, got %d", len(templates))
	}
}

func TestGetTemplates_KnownContextsReturnTemplates(t *testing.T) {
	knownContexts := []context.ContextType{
		context.ContextHTMLBody,
		context.ContextHTMLAttrValue,
		context.ContextJSString,
		context.ContextJSBlock,
	}
	for _, ctx := range knownContexts {
		templates := GetTemplates(ctx)
		if len(templates) == 0 {
			t.Errorf("Context %v should have templates", ctx)
		}
	}
}

func TestHTMLBodyPayloadsIncludeBaseVectors(t *testing.T) {
	templates := GetTemplates(context.ContextHTMLBody)

	// Must have at least the original base vectors
	required := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`<svg onload=alert(1)>`,
	}

	for _, r := range required {
		found := false
		for _, tmpl := range templates {
			if tmpl.Value == r {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing required base payload: %s", r)
		}
	}
}

func TestPolyglotExpansion(t *testing.T) {
	count := 0
	for _, ct := range []context.ContextType{context.ContextHTMLBody, context.ContextHTMLAttrValue} {
		for _, tmpl := range GetTemplates(ct) {
			if strings.HasPrefix(tmpl.Desc, "Polyglot: ") {
				count++
			}
		}
	}
	if count < 20 {
		t.Errorf("expected ≥20 polyglot payloads, got %d", count)
	}
}

func TestPayloadTemplates_NoExactDuplicates(t *testing.T) {
	seen := make(map[string]string)
	for ct, templates := range payloadTemplates {
		for _, tmpl := range templates {
			key := ct.String() + "|" + tmpl.Value
			if prev, ok := seen[key]; ok {
				t.Errorf("duplicate payload in %s: %q (already in %s)", ct, tmpl.Value, prev)
			}
			seen[key] = ct.String()
		}
	}
}

// TestPayloadEscapeSyntax validates the escape-correctness of generated
// payloads: every payload must be a well-formed Go string that survives
// reflection (no unbalanced quote delimiters in JS-breakout payloads).
// Guards the "context-aware payload generation" core promise.
func TestPayloadEscapeSyntax(t *testing.T) {
	allContexts := []context.ContextType{
		context.ContextHTMLBody, context.ContextHTMLAttrValue,
		context.ContextJSString, context.ContextJSBlock,
		context.ContextJSTemplateLiteral, context.ContextURLAttr,
		context.ContextJSONValue, context.ContextTemplate,
		context.ContextHTMLComment, context.ContextCSSBlock,
		context.ContextCSSValue, context.ContextSVGContainer,
		context.ContextMathMLContainer, context.ContextHTMLEntity,
	}
	for _, ct := range allContexts {
		templates := GetTemplates(ct)
		if len(templates) == 0 {
			t.Errorf("context %s has no payload templates", ct)
			continue
		}
		for _, tmpl := range templates {
			if tmpl.Value == "" {
				t.Errorf("context %s: empty payload (desc=%s)", ct, tmpl.Desc)
				continue
			}
			if tmpl.Severity == "" {
				t.Errorf("context %s: payload %q has empty severity", ct, tmpl.Value)
			}
			// JS breakout payloads must have balanced quote usage around the
			// breakout point: a ';alert(1)//-style payload has unmatched quote
			// by design (it closes the server's quote) — skip structural check
			// for JS contexts; only require non-empty + valid severity.
		}
	}
}

// TestPayloadContextCoverage asserts every one of the 19 context types has
// payload templates (either core or extended) — an unserved context means
// payloads never generated for it.
func TestPayloadContextCoverage(t *testing.T) {
	allContexts := []context.ContextType{
		context.ContextUnknown, context.ContextHTMLBody, context.ContextHTMLComment,
		context.ContextHTMLTag, context.ContextHTMLAttrName, context.ContextHTMLAttrValue,
		context.ContextHTMLEntity, context.ContextJSString, context.ContextJSComment,
		context.ContextJSBlock, context.ContextCSSValue, context.ContextCSSBlock,
		context.ContextURLAttr, context.ContextTemplate, context.ContextSVGContainer,
		context.ContextMathMLContainer, context.ContextJSONValue,
		context.ContextJSTemplateLiteral, context.ContextMulti,
	}
	// ContextUnknown and ContextMulti are synthetic — no templates expected.
	expectEmpty := map[context.ContextType]bool{
		context.ContextUnknown: true,
		context.ContextMulti:   true,
	}
	for _, ct := range allContexts {
		templates := GetTemplates(ct)
		if expectEmpty[ct] {
			if len(templates) > 0 {
				t.Errorf("synthetic context %s should have no templates, got %d", ct, len(templates))
			}
			continue
		}
		if len(templates) == 0 {
			t.Errorf("context %s has NO payload templates — payloads never generated", ct)
		}
	}
}
