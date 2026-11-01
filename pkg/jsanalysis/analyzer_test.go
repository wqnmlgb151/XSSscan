package jsanalysis

import (
	"strings"
	"testing"
)

func TestLabeledCorpus(t *testing.T) {
	cases := []struct {
		name, src string
		kind      Kind
		quote     string
	}{
		{"single", `let x='MARKER';`, String, "'"},
		{"escaped", `let x='a\\\'MARKER';`, String, "'"},
		{"quote_in_comment", `/* ' */ let x="MARKER";`, String, `"`},
		{"url_string", `const u="https://host"; MARKER();`, Code, ""},
		{"line_comment", "// MARKER\nlet x=1", Comment, "//"},
		{"unicode_line_end", "// ignored\u2028MARKER()", Code, ""},
		{"block_comment", `/* MARKER */`, Comment, "/*"},
		{"regexp", `let r=/[/'"]MARKER/gi;`, Regexp, "/"},
		{"division", `let x=a / MARKER / b;`, Code, ""},
		{"template_quasi", "let x=`hi MARKER`;", Template, "`"},
		{"template_start", "let x=`MARKER`;", Template, "`"},
		{"template_unicode_start", "let x=`汉MARKER`;", Template, "`"},
		{"template_expr", "let x=`hi ${MARKER()}`;", Code, ""},
		{"nested_template", "let x=`${`hi ${MARKER()}`}`;", Code, ""},
		{"nested_string", "let x=`${foo('MARKER')}`;", String, "'"},
		{"unicode", `let x='汉字 MARKER';`, String, "'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := Parse(tc.src, false)
			s := a.At(strings.Index(tc.src, "MARKER"))
			if a.Error != "" || s.Kind != tc.kind || s.Quote != tc.quote {
				t.Fatalf("want %s %q, got %+v error=%s spans=%+v", tc.kind, tc.quote, s, a.Error, a.Spans)
			}
		})
	}
}

func TestParserFailuresAndCallProvenance(t *testing.T) {
	for _, src := range []string{"let x='unterminated", "import x from 'module';", strings.Repeat("(", maxNesting+1), strings.Repeat("x", MaxSourceBytes+1)} {
		a := Parse(src, false)
		if a.Error == "" || a.At(0).Kind != Unknown || a.HasCallStartingIn(0, len(src)) {
			t.Fatalf("failure treated valid: %+v", a)
		}
	}
	src := `const x="alert(1)"; alert(1);`
	a := Parse(src, false)
	first := strings.Index(src, "alert(1)")
	last := strings.LastIndex(src, "alert(1)")
	if a.HasCallStartingIn(first, first+8) || !a.HasCallStartingIn(last, last+8) {
		t.Fatal("call provenance confused literal and code")
	}
	if a := Parse(`return alert(1)`, true); a.Error != "" || !a.HasCallStartingIn(7, 15) {
		t.Fatalf("handler failed: %+v", a)
	}
}

func FuzzParseBounded(f *testing.F) {
	for _, s := range []string{`const x="marker";`, `let x=/marker/;`, `/*marker*/`, `let x=` + "`${marker}`", `const q=new URLSearchParams(location.search).get('view');const show=x=>el.innerHTML=x;show(q);`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		for _, mode := range []SourceMode{ScriptMode, HandlerMode, ModuleMode} {
			a := parseUncached(s, mode)
			if a.Error == "" {
				for _, sp := range a.Spans {
					if sp.Start < 0 || sp.End > len(s) || sp.Start >= sp.End {
						t.Fatalf("invalid span %+v", sp)
					}
				}
				for _, flow := range a.Flows {
					if flow.Source.Start < 0 || flow.Source.End > len(s) || flow.Source.Start >= flow.Source.End || flow.Start < 0 || flow.End > len(s) || flow.Start >= flow.End {
						t.Fatalf("invalid flow byte ranges %+v", flow)
					}
				}
			}
		}
	})
}

func TestTaggedTemplateAndConstructorProvenance(t *testing.T) {
	for _, s := range []string{"alert`1`", "new Callable('value')"} {
		a := Parse(s, false)
		if a.Error != "" || !a.HasCallStartingIn(0, len(s)) {
			t.Fatalf("invocation missed: %+v", a)
		}
	}
	a := Parse("const x=`alert(1)`", false)
	if a.HasCallStartingIn(0, 100) {
		t.Fatal("ordinary template executed")
	}
}
