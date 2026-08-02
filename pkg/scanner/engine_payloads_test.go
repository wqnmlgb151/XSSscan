package scanner

import (
	"testing"

	"github.com/xsscan/xsscan/pkg/analyze"
	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
)

// --- payloadsFromTemplates ---

func TestPayloadsFromTemplates_Empty(t *testing.T) {
	result := payloadsFromTemplates(nil, payload.PayloadTypeReflected, 0.8)
	if len(result) != 0 {
		t.Errorf("Expected empty slice for nil input, got %v", result)
	}
}

func TestPayloadsFromTemplates_Single(t *testing.T) {
	tmpls := []payload.PayloadTemplate{
		{Value: "<script>alert(1)</script>", Context: ctx.ContextHTMLBody, Severity: model.High},
	}
	result := payloadsFromTemplates(tmpls, payload.PayloadTypeReflected, 0.75)
	if len(result) != 1 {
		t.Fatalf("Expected 1 payload, got %d", len(result))
	}
	if result[0].Value != "<script>alert(1)</script>" {
		t.Errorf("Wrong value: %s", result[0].Value)
	}
	if result[0].Type != payload.PayloadTypeReflected {
		t.Errorf("Wrong type: %s", result[0].Type)
	}
	if result[0].Score != 0.75 {
		t.Errorf("Wrong score: %f", result[0].Score)
	}
	if result[0].Context != ctx.ContextHTMLBody {
		t.Errorf("Wrong context: %s", result[0].Context)
	}
}

func TestPayloadsFromTemplates_Multiple(t *testing.T) {
	tmpls := []payload.PayloadTemplate{
		{Value: "a", Context: ctx.ContextHTMLBody},
		{Value: "b", Context: ctx.ContextJSString},
		{Value: "c", Context: ctx.ContextHTMLAttrValue},
	}
	result := payloadsFromTemplates(tmpls, payload.PayloadTypeReflected, 0.8)
	if len(result) != 3 {
		t.Fatalf("Expected 3 payloads, got %d", len(result))
	}
	// Each template's context should be preserved
	if result[1].Context != ctx.ContextJSString {
		t.Errorf("Expected js_string context, got %s", result[1].Context)
	}
	// All should share the same type and score
	for i, p := range result {
		if p.Type != payload.PayloadTypeReflected {
			t.Errorf("Payload %d: wrong type %s", i, p.Type)
		}
		if p.Score != 0.8 {
			t.Errorf("Payload %d: wrong score %f", i, p.Score)
		}
	}
}

// --- generatePayloads ---

func TestGeneratePayloads_BasicInjection(t *testing.T) {
	engine := &Engine{
		generator: payload.NewGenerator(),
		config:    Config{WAFBypass: false},
	}

	inj := model.InjectionPoint{
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}

	payloads := engine.generatePayloads(inj, nil)
	if len(payloads) == 0 {
		t.Fatal("Expected at least one payload for HTML body context")
	}

	// Should include context-specific payloads + polyglots
	hasPolyglot := false
	for _, p := range payloads {
		if p.Score == 0.8 {
			hasPolyglot = true
			break
		}
	}
	if !hasPolyglot {
		t.Error("Expected polyglot payloads (score 0.8) in output")
	}
}

func TestGeneratePayloads_NoWAFBypass(t *testing.T) {
	engine := &Engine{
		generator: payload.NewGenerator(),
		config:    Config{WAFBypass: false},
	}

	inj := model.InjectionPoint{
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}

	payloads := engine.generatePayloads(inj, nil)

	// WAF bypass payloads have score 0.7 — should NOT be present
	for _, p := range payloads {
		if p.Score == 0.7 {
			t.Error("WAF bypass payloads should not be included when WAFBypass=false")
		}
	}
}

func TestGeneratePayloads_WithWAFBypass(t *testing.T) {
	engine := &Engine{
		generator: payload.NewGenerator(),
		config:    Config{WAFBypass: true},
	}

	inj := model.InjectionPoint{
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}

	payloads := engine.generatePayloads(inj, nil)

	// WAF bypass payloads have score 0.7 — should be present
	hasWAF := false
	for _, p := range payloads {
		if p.Score == 0.7 {
			hasWAF = true
			break
		}
	}
	if !hasWAF {
		t.Error("WAF bypass payloads should be included when WAFBypass=true")
	}
}

func TestGeneratePayloads_FrameworkPayloads(t *testing.T) {
	engine := &Engine{
		generator: payload.NewGenerator(),
		config:    Config{WAFBypass: false},
	}

	inj := model.InjectionPoint{
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}

	frameworks := []analyze.FrameworkInfo{
		{Name: "React", Confidence: 0.9},
	}

	payloads := engine.generatePayloads(inj, frameworks)

	// Framework payloads have score 0.75
	hasFramework := false
	for _, p := range payloads {
		if p.Score == 0.75 {
			hasFramework = true
			break
		}
	}
	if !hasFramework {
		t.Error("Expected framework-specific payloads (score 0.75) for React")
	}
}

func TestGeneratePayloads_DOMXSSESinks(t *testing.T) {
	engine := &Engine{
		generator: payload.NewGenerator(),
		config:    Config{WAFBypass: false},
	}

	inj := model.InjectionPoint{
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{{Type: ctx.ContextHTMLBody}},
	}

	// React has RiskInfo → should produce DOM XSS payloads
	frameworks := []analyze.FrameworkInfo{
		{Name: "React", Confidence: 0.9},
	}

	payloads := engine.generatePayloads(inj, frameworks)

	// DOM payloads have Type=PayloadTypeDOM and Score=0.7
	hasDOM := false
	for _, p := range payloads {
		if p.Type == payload.PayloadTypeDOM {
			hasDOM = true
			break
		}
	}
	if !hasDOM {
		t.Error("Expected DOM XSS payloads for React framework")
	}
}

func TestGeneratePayloads_NoContextFallsBack(t *testing.T) {
	engine := &Engine{
		generator: payload.NewGenerator(),
		config:    Config{WAFBypass: false},
	}

	// No contexts detected — generator falls back to HTML body templates
	inj := model.InjectionPoint{
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  nil,
	}

	payloads := engine.generatePayloads(inj, nil)
	if len(payloads) == 0 {
		t.Fatal("Expected fallback payloads even with no detected contexts")
	}
}

func TestGeneratePayloads_MultipleContexts(t *testing.T) {
	engine := &Engine{
		generator: payload.NewGenerator(),
		config:    Config{WAFBypass: false},
	}

	inj := model.InjectionPoint{
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts: []ctx.Context{
			{Type: ctx.ContextHTMLBody},
			{Type: ctx.ContextJSString},
		},
	}

	payloads := engine.generatePayloads(inj, nil)

	// Should have payloads for both contexts
	hasHTML := false
	hasJS := false
	for _, p := range payloads {
		if p.Context == ctx.ContextHTMLBody {
			hasHTML = true
		}
		if p.Context == ctx.ContextJSString {
			hasJS = true
		}
	}
	if !hasHTML || !hasJS {
		t.Errorf("Expected payloads for both HTML and JS contexts (hasHTML=%v, hasJS=%v)", hasHTML, hasJS)
	}
}
