package context

import (
	"testing"
)

func TestASTContextOccurrencesAndInertScriptData(t *testing.T) {
	d := NewDetector()
	source := "<script>/* ' */ let a='MARKER'; let b=\"MARKER\"; let c=`${MARKER()}`; let d=/MARKER/;</script>"
	got, _ := d.Detect(Reflection{Content: source, ParamValue: "MARKER"})
	if len(got) != 4 {
		t.Fatalf("duplicate or missing occurrences: %+v", got)
	}
	quotes := map[string]bool{}
	for _, c := range got {
		if c.ParseError != "" || source[c.SourceStart:c.SourceEnd] != "MARKER" {
			t.Fatalf("invalid AST span %+v", c)
		}
		if c.Type == ContextJSString {
			quotes[c.QuoteChar] = true
		}
	}
	if !quotes["'"] || !quotes[`"`] {
		t.Fatalf("quotes collapsed: %+v", got)
	}
	for _, source := range []string{`<script type="application/json">{"x":"MARKER"}</script>`, `<script src="a.js">MARKER</script>`} {
		got, _ := d.Detect(Reflection{Content: source, ParamValue: "MARKER"})
		for _, c := range got {
			if c.IsExploitable() {
				t.Fatalf("inert data treated as JS: %+v", c)
			}
		}
	}
	got, _ = d.Detect(Reflection{Content: `<button onclick="return foo('MARKER')">`, ParamValue: "MARKER"})
	if len(got) != 1 || got[0].Type != ContextJSString || got[0].QuoteChar != "'" || got[0].SpanUnit != "attribute_value_bytes" {
		t.Fatalf("handler inner quote lost: %+v", got)
	}
	got, _ = d.Detect(Reflection{Content: `<script>import x from 'm'; let a='MARKER';</script>`, ParamValue: "MARKER"})
	if len(got) == 0 || got[0].ParseError == "" || got[0].Type != ContextUnknown {
		t.Fatalf("unsupported module silently valid: %+v", got)
	}
}

func TestModuleContextClassification(t *testing.T) {
	for _, tc := range []struct {
		source string
		kind   ContextType
	}{
		{`<script type="module">import x from 'MARKER';</script>`, ContextJSString},
		{`<script TYPE=" Module ">export const x='汉MARKER';</script>`, ContextJSString},
		{`<script type="module">await MARKER();</script>`, ContextJSBlock},
		{"<script type=module>export const x=`${MARKER()}`;</script>", ContextJSBlock},
		{`<script type="module">export const x=; MARKER();</script>`, ContextUnknown},
	} {
		got, _ := NewDetector().Detect(Reflection{Content: tc.source, ParamValue: "MARKER"})
		if len(got) != 1 || got[0].Type != tc.kind || got[0].AnalysisMethod != "sobek-ast" {
			t.Fatalf("module context mismatch: %s %+v", tc.source, got)
		}
		if tc.source[got[0].SourceStart:got[0].SourceEnd] != "MARKER" {
			t.Fatal("module byte offset changed")
		}
	}
}
