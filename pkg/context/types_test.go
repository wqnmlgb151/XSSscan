package context

import "testing"

func TestContextTypeIsExploitableType(t *testing.T) {
	tests := []struct {
		ctx      ContextType
		expected bool
	}{
		{ContextUnknown, false},
		{ContextHTMLBody, true},
		{ContextHTMLComment, false},
		{ContextHTMLTag, true},
		{ContextHTMLAttrName, true},
		{ContextHTMLAttrValue, true},
		{ContextHTMLEntity, false},
		{ContextJSString, true},
		{ContextJSComment, false},
		{ContextJSBlock, true},
		{ContextCSSValue, false},
		{ContextCSSBlock, false},
		{ContextURLAttr, true},
		{ContextTemplate, true},
		{ContextSVGContainer, true},
		{ContextMathMLContainer, true},
		{ContextMulti, false},
	}
	for _, tt := range tests {
		t.Run(tt.ctx.String(), func(t *testing.T) {
			if got := tt.ctx.IsExploitableType(); got != tt.expected {
				t.Errorf("ContextType(%s).IsExploitableType() = %v, want %v", tt.ctx, got, tt.expected)
			}
		})
	}
}

func TestContextIsExploitableWithEscape(t *testing.T) {
	tests := []struct {
		name     string
		ctx      Context
		expected bool
	}{
		{"html_body not escaped", Context{Type: ContextHTMLBody}, true},
		{"html_body escaped", Context{Type: ContextHTMLBody, Escaped: true}, false},
		{"js_string not escaped", Context{Type: ContextJSString}, true},
		{"js_string escaped", Context{Type: ContextJSString, Escaped: true}, false},
		{"html_comment not escaped", Context{Type: ContextHTMLComment}, false},
		{"css_block not escaped", Context{Type: ContextCSSBlock}, false},
		{"entity not escaped", Context{Type: ContextHTMLEntity}, false},
		{"svg_container not escaped", Context{Type: ContextSVGContainer}, true},
		{"svg_container escaped", Context{Type: ContextSVGContainer, Escaped: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ctx.IsExploitable(); got != tt.expected {
				t.Errorf("Context{Type:%s, Escaped:%v}.IsExploitable() = %v, want %v",
					tt.ctx.Type, tt.ctx.Escaped, got, tt.expected)
			}
		})
	}
}

func TestParseContextType(t *testing.T) {
	tests := []struct {
		input    string
		expected ContextType
	}{
		{"html_body", ContextHTMLBody},
		{"html_comment", ContextHTMLComment},
		{"html_tag", ContextHTMLTag},
		{"html_attr_name", ContextHTMLAttrName},
		{"html_attr_value", ContextHTMLAttrValue},
		{"html_entity", ContextHTMLEntity},
		{"js_string", ContextJSString},
		{"js_comment", ContextJSComment},
		{"js_block", ContextJSBlock},
		{"css_value", ContextCSSValue},
		{"css_block", ContextCSSBlock},
		{"url_attribute", ContextURLAttr},
		{"template", ContextTemplate},
		{"svg_container", ContextSVGContainer},
		{"mathml_container", ContextMathMLContainer},
		{"multi", ContextMulti},
		{"unknown", ContextUnknown},
		{"INVALID", ContextUnknown},
		{"", ContextUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseContextType(tt.input); got != tt.expected {
				t.Errorf("ParseContextType(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestContextTypeStringRoundTrip(t *testing.T) {
	types := []ContextType{
		ContextUnknown, ContextHTMLBody, ContextHTMLComment, ContextHTMLTag,
		ContextHTMLAttrName, ContextHTMLAttrValue, ContextHTMLEntity,
		ContextJSString, ContextJSComment, ContextJSBlock,
		ContextCSSValue, ContextCSSBlock, ContextURLAttr,
		ContextTemplate, ContextSVGContainer, ContextMathMLContainer, ContextMulti,
	}
	for _, ct := range types {
		t.Run(ct.String(), func(t *testing.T) {
			parsed := ParseContextType(ct.String())
			if parsed != ct {
				t.Errorf("ParseContextType(%q) = %v, want %v", ct.String(), parsed, ct)
			}
		})
	}
}

func TestContextTypeString(t *testing.T) {
	tests := []struct {
		ctx      ContextType
		expected string
	}{
		{ContextHTMLBody, "html_body"},
		{ContextJSString, "js_string"},
		{ContextSVGContainer, "svg_container"},
		{ContextUnknown, "unknown"},
		{ContextType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.ctx.String(); got != tt.expected {
			t.Errorf("ContextType(%d).String() = %q, want %q", tt.ctx, got, tt.expected)
		}
	}
}
