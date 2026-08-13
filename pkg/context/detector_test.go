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

// TestDetectContexts_All19Contexts is the core-accuracy safety net: every one
// of the 19 injection contexts gets ≥3 typical HTML/JS structures and the
// classifier must identify it. Guards the "context-aware" core promise.
func TestDetectContexts_All19Contexts(t *testing.T) {
	const marker = "MARKER"
	d := NewDetector()

	// helper: assert the detected contexts contain the expected type
	assertContains := func(t *testing.T, got []Context, want ContextType) {
		t.Helper()
		for _, c := range got {
			if c.Type == want {
				return
			}
		}
		t.Errorf("detected contexts %v do not contain %s", got, want)
	}

	tests := []struct {
		name     string
		structures []string // 3+ typical reflection structures per context
		want     ContextType
	}{
		{
			name: "html_body",
			structures: []string{
				`<body>MARKER</body>`,
				`<div><p>text MARKER more</p></div>`,
				`<span>MARKER</span>`,
			},
			want: ContextHTMLBody,
		},
		{
			name: "html_comment",
			structures: []string{
				`<!-- MARKER -->`,
				`<div><!-- prefix MARKER suffix --></div>`,
				`<!--\nMARKER\n-->`,
			},
			want: ContextHTMLComment,
		},
		{
			name: "html_tag",
			structures: []string{
				`<MARKER>content</MARKER>`,
				`<MARKER attr="x">`,
				`<MARKER/>`,
			},
			want: ContextHTMLTag,
		},
		{
			name: "html_attr_name",
			structures: []string{
				`<div MARKER="value">`,
				`<input MARKER=1>`,
				`<a MARKER="x" href="/">`,
			},
			want: ContextHTMLAttrName,
		},
		{
			name: "html_attr_value",
			structures: []string{
				`<div title="MARKER">`,
				`<input value='MARKER'>`,
				`<a data-x=MARKER href="/">`,
			},
			want: ContextHTMLAttrValue,
		},
		{
			// ContextHTMLEntity marks inert raw-text-element reflections
			// (textarea/title/xmp content cannot execute scripts).
			name: "html_entity",
			structures: []string{
				`<textarea>MARKER</textarea>`,
				`<title>MARKER</title>`,
				`<xmp>MARKER</xmp>`,
			},
			want: ContextHTMLEntity,
		},
		{
			name: "js_string",
			structures: []string{
				`<script>var x = 'MARKER';</script>`,
				`<script>foo("MARKER")</script>`,
				`<script>const s = 'pre MARKER post';</script>`,
			},
			want: ContextJSString,
		},
		{
			name: "js_comment",
			structures: []string{
				`<script>// MARKER</script>`,
				`<script>/* MARKER */</script>`,
				`<script>\n// line MARKER\n</script>`,
			},
			want: ContextJSComment,
		},
		{
			name: "js_block",
			structures: []string{
				`<script>MARKER</script>`,
				`<script>if (x) { MARKER }</script>`,
				`<script>\nMARKER\n</script>`,
			},
			want: ContextJSBlock,
		},
		{
			name: "css_value",
			structures: []string{
				`<div style="color: MARKER">`,
				`<div style="background: url(MARKER)">`,
				`<div style='width: MARKER px'>`,
			},
			want: ContextCSSValue,
		},
		{
			name: "css_block",
			structures: []string{
				`<style>MARKER</style>`,
				`<style>.a { }\nMARKER\n</style>`,
				`<style>\nMARKER { color: red }\n</style>`,
			},
			want: ContextCSSBlock,
		},
		{
			name: "url_attribute",
			structures: []string{
				`<a href="MARKER">x</a>`,
				`<img src='MARKER'>`,
				`<form action=MARKER>`,
			},
			want: ContextURLAttr,
		},
		{
			name: "template",
			structures: []string{
				`<div>{{ MARKER }}</div>`,
				`<p>text {{ MARKER }} text</p>`,
				`{{ MARKER }}`,
			},
			want: ContextTemplate,
		},
		{
			name: "svg_container",
			structures: []string{
				`<svg>MARKER</svg>`,
				`<svg><g>MARKER</g></svg>`,
				`<svg><text>MARKER</text></svg>`,
			},
			want: ContextSVGContainer,
		},
		{
			name: "mathml_container",
			structures: []string{
				`<math>MARKER</math>`,
				`<math><mrow>MARKER</mrow></math>`,
				`<math><mi>MARKER</mi></math>`,
			},
			want: ContextMathMLContainer,
		},
		{
			name: "js_template_literal",
			structures: []string{
				"<script>var x = `MARKER`;</script>",
				"<script>foo(`pre MARKER post`)</script>",
				"<script>const t = `\nMARKER\n`;</script>",
			},
			want: ContextJSTemplateLiteral,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, s := range tt.structures {
				got, err := d.Detect(Reflection{Content: s, ParamValue: marker})
				if err != nil {
					t.Fatalf("structure %d: Detect error: %v", i, err)
				}
				assertContains(t, got, tt.want)
			}
		})
	}
}

// TestDetectContexts_MultipleReflections verifies that a page reflecting the
// marker in several places yields MULTIPLE ranked contexts (the detector
// never synthesizes ContextMulti — callers inspect the ranked slice).
func TestDetectContexts_MultipleReflections(t *testing.T) {
	d := NewDetector()
	got, err := d.Detect(Reflection{
		Content:    `<body>MARKER</body><script>var x='MARKER'</script>`,
		ParamValue: "MARKER",
	})
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(got) < 2 {
		t.Fatalf("expected ≥2 contexts, got %d: %v", len(got), got)
	}
	// Priority-sorted: html_body (100) first, then js_string (85)
	if got[0].Type != ContextHTMLBody {
		t.Errorf("highest-priority context = %s, want html_body", got[0].Type)
	}
}
