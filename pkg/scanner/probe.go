package scanner

import (
	"context"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

/* ContextProbe tests whether a reflection context is actually exploitable
by sending a context-specific probe payload and checking if it reflects
in an unescaped, executable form.

Probes address the marker->payload assumption gap: the scanner detects
reflection context using a random alphanumeric marker (only [a-z0-9]),
but real payloads contain < > " and other chars that may be escaped. */

type ContextProbe struct {
	ContextType ctx.ContextType
	Probe      string
	Validator  func(body string) bool
}

/* GetProbeForContext returns the FIRST probe for a given context type.
The second return value is false if no probe is defined for the context.
Use GetProbesForContext to test all probe dimensions. */

func GetProbeForContext(ct ctx.ContextType) (ContextProbe, bool) {
	probes, ok := probeLibrary[ct]
	if !ok || len(probes) == 0 {
		return ContextProbe{}, false
	}
	return probes[0], true
}

/* GetProbesForContext returns all probe dimensions for a context type.
A context is considered exploitable if ANY dimension's validator passes —
real payloads may use a different breakout mechanism than the primary probe. */

func GetProbesForContext(ct ctx.ContextType) []ContextProbe {
	return probeLibrary[ct]
}

/* probeLibrary maps each context type to its probe dimensions.
Probes are SAFE: no alert(), no side effects, just structural tests.
The first entry is the primary probe; additional entries test alternative
breakout mechanisms (e.g., quote breakout when angle brackets are stripped). */

var probeLibrary = map[ctx.ContextType][]ContextProbe{
	ctx.ContextHTMLBody: {{
		ContextType: ctx.ContextHTMLBody,
		Probe:      "<xsscan>",
		Validator:  validateUnescapedProbe("<xsscan>"),
	}},
	ctx.ContextHTMLComment: {{
		ContextType: ctx.ContextHTMLComment,
		Probe:      "--><xsscan><!--",
		Validator:  validateCommentBreakout,
	}},
	ctx.ContextHTMLTag: {{
		ContextType: ctx.ContextHTMLTag,
		Probe:      "xsscan",
		Validator:  validateUnescapedProbe("xsscan"),
	}},
	ctx.ContextHTMLAttrName: {{
		ContextType: ctx.ContextHTMLAttrName,
		Probe:      "xsscan",
		Validator:  validateUnescapedProbe("xsscan"),
	}},
	ctx.ContextHTMLAttrValue: {
		{
			ContextType: ctx.ContextHTMLAttrValue,
			Probe:      " xsscan>",
			Validator:  validateAttrBreakout,
		},
		// Quote-only breakout: servers that strip < > but preserve quotes
		// are still exploitable via event-handler attribute injection
		// (" onmouseover=alert(1) x="). These probes validate that dimension.
		{
			ContextType: ctx.ContextHTMLAttrValue,
			Probe:      `"xsscan"=`,
			Validator:  validateDoubleQuoteBreakout,
		},
		{
			ContextType: ctx.ContextHTMLAttrValue,
			Probe:      `'xsscan'=`,
			Validator:  validateSingleQuoteBreakout,
		},
	},
	ctx.ContextHTMLEntity: {{
		ContextType: ctx.ContextHTMLEntity,
		Probe:      "xsscan",
		Validator:  validateUnescapedProbe("xsscan"),
	}},
	ctx.ContextJSString: {{
		ContextType: ctx.ContextJSString,
		Probe:      jsStringProbeValue,
		Validator:  validateUnescapedProbe(jsStringProbeValue),
	}},
	ctx.ContextJSComment: {{
		ContextType: ctx.ContextJSComment,
		Probe:      "/*xsscan*/",
		Validator:  validateUnescapedProbe("xsscan"),
	}},
	ctx.ContextJSBlock: {{
		ContextType: ctx.ContextJSBlock,
		Probe:      "</script><xsscan>",
		Validator:  validateUnescapedProbe("<xsscan>"),
	}},
	ctx.ContextCSSValue: {{
		ContextType: ctx.ContextCSSValue,
		Probe:      "xsscan",
		Validator:  validateUnescapedProbe("xsscan"),
	}},
	ctx.ContextCSSBlock: {{
		ContextType: ctx.ContextCSSBlock,
		Probe:      "</style><xsscan><style>",
		Validator:  validateUnescapedProbe("<xsscan>"),
	}},
	ctx.ContextURLAttr: {{
		ContextType: ctx.ContextURLAttr,
		Probe:      "javascript:xsscan",
		Validator:  validateURLBreakout,
	}},
	ctx.ContextTemplate: {{
		ContextType: ctx.ContextTemplate,
		Probe:      "{{xsscan}}",
		Validator:  validateUnescapedProbe("xsscan"),
	}},
	ctx.ContextSVGContainer: {{
		ContextType: ctx.ContextSVGContainer,
		Probe:      "<xsscan>",
		Validator:  validateUnescapedProbe("<xsscan>"),
	}},
	ctx.ContextMathMLContainer: {{
		ContextType: ctx.ContextMathMLContainer,
		Probe:      "<xsscan>",
		Validator:  validateUnescapedProbe("<xsscan>"),
	}},
	ctx.ContextJSONValue: {{
		ContextType: ctx.ContextJSONValue,
		Probe:      jsonProbeValue,
		Validator:  validateJSONBreakout,
	}},
	ctx.ContextJSTemplateLiteral: {{
		ContextType: ctx.ContextJSTemplateLiteral,
		Probe:      templateLiteralProbeValue,
		Validator:  validateUnescapedProbe(templateLiteralProbeValue),
	}},
}

/*
Probe values containing characters that are awkward to embed directly in Go
source (forward-slash sequences, single quotes, double quotes) are assembled
from runes at package init so the probe table stays readable.
*/

var (
	/* jsStringProbeValue = ';xsscan// — breaks out of a single-quoted JS string. */
	jsStringProbeValue = string(rune(0x27)) + ";xsscan" + string([]byte{0x2F, 0x2F})

	/* jsonProbeValue = "xsscan" — breaks out of a JSON string value. */
	jsonProbeValue = string(rune(0x22)) + "xsscan" + string(rune(0x22))

	/* templateLiteralProbeValue = ${xsscan} — tests expression breakout. */
	templateLiteralProbeValue = "${xsscan}"
)

/* validateUnescapedProbe checks that expected appears in the response body
and is not HTML-entity-escaped. If the probe contains < > or ", the escaped
form is also checked — if only the escaped form appears, the probe failed. */

func validateUnescapedProbe(expected string) func(body string) bool {
	hasSpecial := strings.ContainsAny(expected, "<>\"")
	return func(body string) bool {
		if strings.Contains(body, expected) {
			return true
		}
		if hasSpecial {
			escaped := strings.Replace(expected, "<", "&lt;", -1)
			escaped = strings.Replace(escaped, ">", "&gt;", -1)
			escaped = strings.Replace(escaped, "\"", "&quot;", -1)
			if strings.Contains(body, escaped) {
				return false
			}
		}
		return false
	}
}

/* validateCommentBreakout confirms the probe broke out of an HTML comment. */

func validateCommentBreakout(body string) bool {
	return strings.Contains(body, "<xsscan>")
}

/* validateAttrBreakout confirms the probe escaped the attribute value context. */

func validateAttrBreakout(body string) bool {
	return strings.Contains(body, "xsscan>")
}

/* validateQuoteBreakout confirms the probe's quote actually broke out of an
attribute value: the HTML tokenizer must find a tag attribute NAMED xsscan.
Naive substring checks produce false positives when quotes reflect raw in
body text (inert) or inside attribute values without breaking out. */

func validateQuoteBreakout(body string) bool {
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return false
		case html.StartTagToken, html.SelfClosingTagToken:
			// TagAttr must be consumed directly — z.Token() would advance
			// the tokenizer past the tag and corrupt attribute reading.
			for {
				key, _, more := z.TagAttr()
				// HTML5 parses the injected quote as part of the attribute
				// name (parse error but tolerated): value=""xsscan"=" becomes
				// attribute `xsscan"`. Trim quotes before comparison.
				name := strings.Trim(string(key), `"'`)
				if strings.EqualFold(name, "xsscan") {
					return true
				}
				if !more {
					break
				}
			}
		}
	}
}

/* validateDoubleQuoteBreakout and validateSingleQuoteBreakout both delegate
to the tokenizer check — the quote character itself doesn't change the
semantic: an attribute named xsscan proves the value was broken out. */

func validateDoubleQuoteBreakout(body string) bool {
	return validateQuoteBreakout(body)
}

func validateSingleQuoteBreakout(body string) bool {
	return validateQuoteBreakout(body)
}

/* validateURLBreakout confirms javascript: protocol injection was reflected. */

func validateURLBreakout(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "javascript:")
}

/* validateJSONBreakout confirms the probe escaped a JSON string value. */

func validateJSONBreakout(body string) bool {
	return strings.Contains(body, jsonProbeValue)
}

/* runContextProbe sends context-specific probes for each exploitable context
in the injection point. Returns the subset of contexts that passed validation.
If no probe is defined for any context, returns the original contexts (fail-open).
If ALL probed contexts fail, returns nil. */

func (e *Engine) runContextProbe(stdctx context.Context, injection model.InjectionPoint, host string) []ctx.Context {
	// Separate contexts into probed and unprobed categories
	var probed, unprobed []ctx.Context
	for _, c := range injection.Contexts {
		if !c.IsExploitable() {
			continue
		}
		if probes := GetProbesForContext(c.Type); len(probes) > 0 {
			probed = append(probed, c)
		} else {
			unprobed = append(unprobed, c)
		}
	}

	if len(probed) == 0 {
		return injection.Contexts // fail-open: nothing to probe
	}

	// Test each probed context across ALL probe dimensions; keep those
	// where at least one dimension passes. Real payloads may exploit a
	// different breakout mechanism than the primary probe (e.g., quote
	// injection when angle brackets are stripped).
	var passed []ctx.Context
	for _, c := range probed {
		contextPassed := false
		for _, probe := range GetProbesForContext(c.Type) {
			body, err := e.sendProbeRequest(stdctx, injection, probe.Probe, host)
			if err != nil {
				e.logger.Debug("probe request failed (fail open)", zap.Error(err),
					zap.String("param", injection.Parameter.Name),
					zap.String("context", c.Type.String()))
				contextPassed = true // fail-open on network errors
				break
			}
			if probe.Validator(body) {
				contextPassed = true
				break
			}
			e.logger.Debug("context probe dimension failed",
				zap.String("param", injection.Parameter.Name),
				zap.String("context", c.Type.String()),
				zap.String("probe", probe.Probe))
		}
		if contextPassed {
			passed = append(passed, c)
		}
	}

	// Only fail if ALL probed contexts failed AND no unprobed contexts remain
	if len(passed) == 0 && len(unprobed) == 0 {
		return nil
	}
	return append(passed, unprobed...)
}

/* sendProbeRequest injects a probe payload and sends the request, returning
the response body. Reuses the same inject + throttle + client pipeline as
doScanPayload but without retry/WAF logic — probes are one-shot. */

func (e *Engine) sendProbeRequest(stdctx context.Context, injection model.InjectionPoint, probeValue, host string) (string, error) {
	modifiedTarget, err := e.injectPayload(injection.Target, injection.Parameter, probeValue)
	if err != nil {
		return "", fmt.Errorf("probe inject: %w", err)
	}

	if err := ssrfguard.IsURLTargetAllowed(modifiedTarget.URL); err != nil {
		return "", fmt.Errorf("ssrf blocked: %w", err)
	}

	if err := e.throttle.Wait(stdctx, host); err != nil {
		return "", err
	}

	req, err := e.buildRequest(stdctx, modifiedTarget)
	if err != nil {
		return "", err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
	if err != nil {
		return "", err
	}

	e.throttle.ReportSuccessHost(host)
	return string(body), nil
}
