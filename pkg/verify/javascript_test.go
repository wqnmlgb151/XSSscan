package verify

import (
	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"strings"
	"testing"
)

func TestASTResponseLabeledCorpus(t *testing.T) {
	cases := []struct {
		name, body, p string
		kind          ctx.ContextType
		vulnerable    bool
	}{
		{"string_break", `<script>let x=''-alert(1)-'';</script>`, `'-alert(1)-'`, ctx.ContextJSString, true},
		{"module_string_break", `<script type="module">export const x=''-alert(1)-'';</script>`, `'-alert(1)-'`, ctx.ContextJSString, true},
		{"module_await", `<script type="module">await alert(1);</script>`, `alert(1)`, ctx.ContextJSBlock, true},
		{"module_import_string", `<script type="module">import x from 'alert(1)';</script>`, `alert(1)`, ctx.ContextJSBlock, false},
		{"module_export_string", `<script type="module">export const x='alert(1)';</script>`, `alert(1)`, ctx.ContextJSBlock, false},
		{"module_unrelated", `<script type="module">alert(1); export const x='MARKER';</script>`, `MARKER`, ctx.ContextJSString, false},
		{"module_invalid", `<script type="module">export const x=; alert(1);</script>`, `alert(1)`, ctx.ContextJSBlock, false},
		{"module_strict_with", `<script type="module">with({}){alert(1)}</script>`, `alert(1)`, ctx.ContextJSBlock, false},
		{"module_duplicate_params", `<script type="module">function f(a,a){alert(1)}</script>`, `alert(1)`, ctx.ContextJSBlock, false},
		{"wrong_quote", `<script>let x='"-alert(1)-"';</script>`, `"-alert(1)-"`, ctx.ContextJSString, false},
		{"broken_js", `<script>let x='';alert(1);'oops;</script>`, `';alert(1);'`, ctx.ContextJSString, false},
		{"regex_break", `<script>let r=/x/;alert(1);///;</script>`, `x/;alert(1);//`, ctx.ContextJSRegexp, true},
		{"regex_inert", `<script>let r=/alert(1)/;</script>`, `alert(1)`, ctx.ContextJSBlock, false},
		{"comment_inert", `<script>/* alert(1) */</script>`, `alert(1)`, ctx.ContextJSComment, false},
		{"block_break", `<script>/**/alert(1);/**/</script>`, `*/alert(1);/*`, ctx.ContextJSComment, true},
		{"line_break", "<script>//\nalert(1);//</script>", "\nalert(1);//", ctx.ContextJSComment, true},
		{"template_expr", "<script>let x=`${alert(1)}`;</script>", "${alert(1)}", ctx.ContextJSTemplateLiteral, true},
		{"template_literal", "<script>let x=`alert(1)`;</script>", `alert(1)`, ctx.ContextJSBlock, false},
		{"unrelated_call", `<script>alert(1); let x='MARKER';</script>`, `MARKER`, ctx.ContextJSString, false},
		{"handler_break", `<button onclick="foo(''-alert(1)-'')">`, `'-alert(1)-'`, ctx.ContextJSString, true},
		{"handler_invalid", `<img onerror="if( alert(1)">`, `<img onerror="if( alert(1)">`, ctx.ContextHTMLBody, false},
		{"script_invalid", `<script>if( alert(1)</script>`, `<script>if( alert(1)</script>`, ctx.ContextHTMLBody, false},
		{"json_data", `<script type="application/json">"alert(1)"</script>`, `alert(1)`, ctx.ContextJSBlock, false},
		{"tagged_call", "<script>alert`1`</script>", "alert`1`", ctx.ContextJSBlock, true},
		{"tagged_handler", "<img onerror=\"alert`1`\">", "<img onerror=\"alert`1`\">", ctx.ContextHTMLBody, true},
		{"plain_text", "<div>SAFE</div>", "SAFE", ctx.ContextHTMLBody, false},
		{"url_call", `<a href="javascript:alert(1)">go</a>`, `javascript:alert(1)`, ctx.ContextURLAttr, true},
		{"url_string", `<a href="javascript:'alert(1)'">go</a>`, `javascript:'alert(1)'`, ctx.ContextURLAttr, false},
		{"url_broken", `<a href="javascript:if( alert(1)">go</a>`, `javascript:if( alert(1)`, ctx.ContextURLAttr, false},
		{"url_unrelated_call", `<a href="javascript:alert(1);'MARKER'">go</a>`, `MARKER`, ctx.ContextURLAttr, false},
		{"url_repeated", `<a href="javascript:'alert(1)';alert(1)">go</a>`, `alert(1)`, ctx.ContextURLAttr, true},
		{"url_encoded", `<a href="javascript:alert%281%29">go</a>`, `javascript:alert%281%29`, ctx.ContextURLAttr, true},
		{"data_unrelated_call", `<iframe src="data:text/html,<script>alert(1)</script><p>MARKER</p>">`, `MARKER`, ctx.ContextURLAttr, false},
		{"srcdoc_unrelated_call", `<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;MARKER">`, `MARKER`, ctx.ContextHTMLBody, false},
		{"handler_repeated", `<button onclick="const s='alert(1)';alert(1)">`, `alert(1)`, ctx.ContextJSBlock, true},
		{"template_unrelated_call", `<template><script>alert(1)</script></template><script>let x='alert(1)';</script>`, `alert(1)`, ctx.ContextJSString, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewVerifier()
			got := v.Verify(tc.body, strings.ToLower(tc.body), payload.Payload{Value: tc.p, Context: tc.kind}, model.InjectionPoint{}, nil, WAFResult{})
			if got.Vulnerable != tc.vulnerable {
				t.Fatalf("want vulnerable=%t: %+v", tc.vulnerable, got)
			}
			if got.Vulnerable && (got.Evidence.AnalysisMethod != "sobek-ast" || got.Confidence > MaxUnverifiedConfidence) {
				t.Fatalf("no AST provenance/cap: %+v", got)
			}
		})
	}
}
