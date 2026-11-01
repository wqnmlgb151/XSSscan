package verify

import (
	"strings"
	"testing"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
)

func TestVerify_ResponseContext(t *testing.T) {
	for _, tc := range []struct {
		name, body, value string
		claimed           ctx.ContextType
		want              bool
	}{
		{"html", `<div><img src=x onerror=alert(1)></div>`, `<img src=x onerror=alert(1)>`, ctx.ContextHTMLBody, true},
		{"textarea", `<textarea><img src=x onerror=alert(1)></textarea>`, `<img src=x onerror=alert(1)>`, ctx.ContextHTMLBody, false},
		{"title", `<title><img src=x onerror=alert(1)></title>`, `<img src=x onerror=alert(1)>`, ctx.ContextHTMLBody, false},
		{"comment", `<!-- <img src=x onerror=alert(1)> -->`, `<img src=x onerror=alert(1)>`, ctx.ContextHTMLBody, false},
		{"quoted attribute", `<div title='<img src=x onerror=alert(1)>'></div>`, `<img src=x onerror=alert(1)>`, ctx.ContextHTMLBody, false},
		{"script string", `<script>var x='<img src=x onerror=alert(1)>';</script>`, `<img src=x onerror=alert(1)>`, ctx.ContextHTMLBody, false},
		{"JS in text", `<div>';alert(1)//</div>`, `';alert(1)//`, ctx.ContextJSString, false},
		{"JS single quote", `<script>var x='';alert(1)//';</script>`, `';alert(1)//`, ctx.ContextJSString, true},
		{"JS wrong quote", `<script>var x="';alert(1)//";</script>`, `';alert(1)//`, ctx.ContextJSString, false},
		{"JS block in string", `<script>var x="alert(1)";</script>`, `alert(1)`, ctx.ContextJSBlock, false},
		{"URL query", `<a href="/search?q=javascript:alert(1)">link</a>`, `javascript:alert(1)`, ctx.ContextURLAttr, false},
		{"URL start", `<a href="javascript:alert(1)">link</a>`, `javascript:alert(1)`, ctx.ContextURLAttr, true},
		{"raw text breakout", `<textarea></textarea><img src=x onerror=alert(1)>`, `</textarea><img src=x onerror=alert(1)>`, ctx.ContextHTMLBody, true},
		{"comment breakout", `<!-- --><img src=x onerror=alert(1)> -->`, `--><img src=x onerror=alert(1)>`, ctx.ContextHTMLBody, true},
		{"inert then active", `<textarea><img src=x onerror=alert(1)></textarea><div><img src=x onerror=alert(1)></div>`, `<img src=x onerror=alert(1)>`, ctx.ContextHTMLBody, true},
		{"unrelated sink", `<img src=x onerror=alert(1)><textarea><svg onload=alert(2)></textarea>`, `<svg onload=alert(2)>`, ctx.ContextHTMLBody, false},
		{"script data", `<script type="application/json">"';alert(1)//"</script>`, `';alert(1)//`, ctx.ContextJSString, false},
		{"framework expression", `<div>{{constructor.constructor('alert(1)')()}}</div>`, `{{constructor.constructor('alert(1)')()}}`, ctx.ContextTemplate, true},
		{"framework expression in raw text", `<textarea>{{constructor.constructor('alert(1)')()}}</textarea>`, `{{constructor.constructor('alert(1)')()}}`, ctx.ContextTemplate, false},
		{"framework expression in JS string", `<script>var x="{{constructor.constructor('alert(1)')()}}";</script>`, `{{constructor.constructor('alert(1)')()}}`, ctx.ContextTemplate, false},
		{"handler name in quoted text", `<div onerror="void 0" title="onerror=alert(1)"></div>`, `onerror=alert(1)`, ctx.ContextHTMLAttrName, false},
		{"duplicate handler", `<img onerror="void 0" onerror=alert(1)>`, `onerror=alert(1)`, ctx.ContextHTMLAttrName, false},
		{"template element", `<template><script>alert(1)</script></template>`, `<script>alert(1)</script>`, ctx.ContextHTMLBody, false},
		{"external script inline text", `<script src="/safe.js">alert(1)</script>`, `alert(1)`, ctx.ContextJSBlock, false},
		{"injected external script", `<div><script src="/injected.js"></script></div>`, `<script src="/injected.js"></script>`, ctx.ContextHTMLBody, false},
		{"unproven external base payload", `<div><base href="//evil.com/"><script src="/cdn.js"></script></div>`, `<base href="//evil.com/"><script src="/cdn.js"></script>`, ctx.ContextHTMLBody, false},
		{"event quote breakout", `<input value="" onmouseover=alert(1) x="">`, `" onmouseover=alert(1) x="`, ctx.ContextHTMLAttrValue, true},
		{"handler in ordinary attribute", `<input value='" onmouseover=alert(1) x="'>`, `" onmouseover=alert(1) x="`, ctx.ContextHTMLAttrValue, false},
		{"link quote breakout", `<div title=""><a href=javascript:alert(1)>XSS</a></div>`, `"><a href=javascript:alert(1)>XSS</a>`, ctx.ContextHTMLAttrValue, true},
		{"srcdoc quote breakout", `<div title=""><iframe srcdoc="<script>alert(1)</script>"></iframe>`, `"><iframe srcdoc="<script>alert(1)</script>">`, ctx.ContextHTMLAttrValue, true},
		{"srcdoc inert markup", `<iframe srcdoc="<textarea><script>alert(1)</script></textarea>"></iframe>`, `<iframe srcdoc="<textarea><script>alert(1)</script></textarea>">`, ctx.ContextHTMLAttrValue, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := payload.Payload{Value: tc.value, Context: tc.claimed}
			result := NewVerifier().Verify(tc.body, strings.ToLower(tc.body), p, model.InjectionPoint{}, nil, WAFResult{})
			if result.Vulnerable != tc.want {
				t.Fatalf("got %+v, want vulnerable=%v", result, tc.want)
			}
		})
	}
}

func TestVerify_RepeatedInertReflectionsThenExecution(t *testing.T) {
	value := `alert(1)`
	body := strings.Repeat("<textarea>"+value+"</textarea>", 5000)
	p := payload.Payload{Value: value, Context: ctx.ContextJSBlock}
	v := NewVerifier()
	if got := v.Verify(body, strings.ToLower(body), p, model.InjectionPoint{}, nil, WAFResult{}); got.Vulnerable {
		t.Fatal("Inert reflections accepted")
	}
	body += "<script>" + value + "</script>"
	if got := v.Verify(body, strings.ToLower(body), p, model.InjectionPoint{}, nil, WAFResult{}); !got.Vulnerable {
		t.Fatalf("Active reflection missed: %+v", got)
	}
}

func BenchmarkVerify_RepeatedInertReflections(b *testing.B) {
	value := `alert(1)`
	body := strings.Repeat("<textarea>"+value+"</textarea>", 5000)
	lower := strings.ToLower(body)
	p := payload.Payload{Value: value, Context: ctx.ContextJSBlock}
	v := NewVerifier()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.Verify(body, lower, p, model.InjectionPoint{}, nil, WAFResult{})
	}
}

func TestVerify_ResponseMediaType(t *testing.T) {
	body := `<img src=x onerror=alert(1)>`
	p := payload.Payload{Value: body, Context: ctx.ContextHTMLBody}
	for _, tc := range []struct {
		contentType string
		want        bool
	}{
		{"text/html; charset=utf-8", true},
		{"text/plain", false},
		{"application/json", false},
		{"application/javascript", false},
		{"application/octet-stream", false},
		{"text/html; malformed", false},
	} {
		got := NewVerifier().VerifyWithThreshold(body, strings.ToLower(body), p, model.InjectionPoint{}, nil, WAFResult{}, DefaultConfidenceThreshold, tc.contentType)
		if got.Vulnerable != tc.want {
			t.Fatalf("%s: %+v", tc.contentType, got)
		}
	}
}
