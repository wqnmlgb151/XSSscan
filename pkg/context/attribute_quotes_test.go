package context

import "testing"

func TestDetectedAttributeQuote(t *testing.T) {
	for _, tc := range []struct{ tag, quote string }{
		{`<input value="MARKER">`, `"`}, {`<input value='MARKER'>`, "'"},
		{`<input value=MARKER>`, ""}, {`<input disabled TITLE = 'x>y' VALUE = "MARKER"/>`, `"`},
		{`<input title="&quot;" value='MARKER'>`, "'"},
		{`<input value='&quot;MARKER'>`, "'"},
		{`<input a=b/c value='MARKER'>`, "'"},
		{`<input a=b"c value='MARKER'>`, "'"},
		{`<input =odd='x' value="MARKER">`, `"`},
		{"<input\tvalue\n=\r'MARKER'>", "'"},
	} {
		got, _ := NewDetector().Detect(Reflection{Content: tc.tag, ParamValue: "MARKER"})
		found := false
		for _, c := range got {
			if c.Type == ContextHTMLAttrValue && c.AttrName == "value" {
				found = true
				if c.QuoteChar != tc.quote {
					t.Errorf("tag=%s quote=%q want=%q", tc.tag, c.QuoteChar, tc.quote)
				}
			}
		}
		if !found {
			t.Fatalf("no attribute: %s %+v", tc.tag, got)
		}
	}
}

func TestEventHandlerRetainsInnerJSQuote(t *testing.T) {
	got, _ := NewDetector().Detect(Reflection{Content: `<input onclick="foo('MARKER')">`, ParamValue: "MARKER"})
	if len(got) != 1 || got[0].Type != ContextJSString || got[0].QuoteChar != "'" {
		t.Fatal(got)
	}
}

func TestDuplicateAttributesKeepQuoteConservative(t *testing.T) {
	got, _ := NewDetector().Detect(Reflection{Content: `<input a=1 a="2" value='MARKER'>`, ParamValue: "MARKER"})
	found := false
	for _, c := range got {
		if c.AttrName == "value" {
			found = true
			if c.QuoteChar != "" && c.QuoteChar != "'" {
				t.Fatalf("borrowed duplicate quote: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("lost reflection after duplicate attribute")
	}
}
