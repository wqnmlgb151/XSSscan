package context

import (
	"testing"
)

func TestEventHandlerAttributeClassifiedAsJS(t *testing.T) {
	d := NewDetector()

	// Payload inside onerror attribute — should be JS context, not HTML attribute
	ref := Reflection{
		Content:    `<img src="x" onerror="MARKER">`,
		Offset:     26,
		ParamValue: "MARKER",
	}
	contexts, err := d.Detect(ref)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	if len(contexts) == 0 {
		t.Fatal("Expected contexts but got none")
	}

	// The event handler attribute should be classified as JS context
	found := false
	for _, ctx := range contexts {
		if ctx.Type == ContextJSBlock && ctx.AttrName == "onerror" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected ContextJSBlock for onerror attribute, got contexts: %v", contexts)
	}
}

func TestOnClickAttributeClassifiedAsJS(t *testing.T) {
	d := NewDetector()

	ref := Reflection{
		Content:    `<button onclick="MARKER">Click</button>`,
		Offset:     18,
		ParamValue: "MARKER",
	}
	contexts, err := d.Detect(ref)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, ctx := range contexts {
		if ctx.Type == ContextJSBlock && ctx.AttrName == "onclick" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected ContextJSBlock for onclick attribute, got: %v", contexts)
	}
}

func TestNormalAttributeRemainsHTMLAttrValue(t *testing.T) {
	d := NewDetector()

	ref := Reflection{
		Content:    `<div class="MARKER">content</div>`,
		Offset:     14,
		ParamValue: "MARKER",
	}
	contexts, err := d.Detect(ref)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, ctx := range contexts {
		if ctx.Type == ContextHTMLAttrValue && ctx.AttrName == "class" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected ContextHTMLAttrValue for class attribute, got: %v", contexts)
	}
}

func TestHrefAttributeClassifiedAsURL(t *testing.T) {
	d := NewDetector()

	ref := Reflection{
		Content:    `<a href="MARKER">link</a>`,
		Offset:     9,
		ParamValue: "MARKER",
	}
	contexts, err := d.Detect(ref)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, ctx := range contexts {
		if ctx.Type == ContextURLAttr && ctx.AttrName == "href" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected ContextURLAttr for href attribute, got: %v", contexts)
	}
}

func TestStyleAttributeClassifiedAsCSS(t *testing.T) {
	d := NewDetector()

	ref := Reflection{
		Content:    `<div style="color: MARKER">content</div>`,
		Offset:     20,
		ParamValue: "MARKER",
	}
	contexts, err := d.Detect(ref)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, ctx := range contexts {
		if ctx.Type == ContextCSSValue && ctx.AttrName == "style" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected ContextCSSValue for style attribute, got: %v", contexts)
	}
}

func TestSVGContextDetected(t *testing.T) {
	d := NewDetector()
	ref := Reflection{
		Content:    `<svg><text>MARKER</text></svg>`,
		Offset:     11,
		ParamValue: "MARKER",
	}
	contexts, err := d.Detect(ref)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, ctx := range contexts {
		if ctx.Type == ContextSVGContainer {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected ContextSVGContainer for text inside <svg>, got: %v", contexts)
	}
}

func TestMathMLContextDetected(t *testing.T) {
	d := NewDetector()
	ref := Reflection{
		Content:    `<math><mi>MARKER</mi></math>`,
		Offset:     11,
		ParamValue: "MARKER",
	}
	contexts, err := d.Detect(ref)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, ctx := range contexts {
		if ctx.Type == ContextMathMLContainer {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected ContextMathMLContainer for text inside <math>, got: %v", contexts)
	}
}

func TestSVGContextTerminatesOnEndTag(t *testing.T) {
	d := NewDetector()
	ref := Reflection{
		Content:    `<svg>MARKER</svg><div>MARKER</div>`,
		Offset:     5,
		ParamValue: "MARKER",
	}
	contexts, err := d.Detect(ref)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// First MARKER should be in SVG context
	// Second MARKER should be in HTMLBody context
	hasSVG := false
	hasHTMLBody := false
	for _, ctx := range contexts {
		if ctx.Type == ContextSVGContainer {
			hasSVG = true
		}
		if ctx.Type == ContextHTMLBody {
			hasHTMLBody = true
		}
	}
	if !hasSVG {
		t.Errorf("Expected SVG context for first MARKER, got: %v", contexts)
	}
	if !hasHTMLBody {
		t.Errorf("Expected HTMLBody context for second MARKER, got: %v", contexts)
	}
}

func TestOnloadAttributeInIMG(t *testing.T) {
	d := NewDetector()

	ref := Reflection{
		Content:    `<img src="x" onload="MARKER">`,
		Offset:     23,
		ParamValue: "MARKER",
	}
	contexts, err := d.Detect(ref)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, ctx := range contexts {
		if ctx.Type == ContextJSBlock && ctx.AttrName == "onload" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected ContextJSBlock for onload attribute, got: %v", contexts)
	}
}
