package scanner

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
	ctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/httpclient"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
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
	Probe       string
	Validator   func(body string) bool
}

/* GetProbeForContext returns the FIRST probe for a given context type.
The second return value is false if no probe is defined for the context.
Use GetProbesForContext to test all probe dimensions. */

func GetProbeForContext(ct ctx.ContextType, prefixes ...string) (ContextProbe, bool) {
	probes := GetProbesForContext(ct, prefixes...)
	if len(probes) == 0 {
		return ContextProbe{}, false
	}
	return probes[0], true
}

/* GetProbesForContext returns all probe dimensions for a context type.
A context is considered exploitable if ANY dimension's validator passes —
real payloads may use a different breakout mechanism than the primary probe. */

func GetProbesForContext(ct ctx.ContextType, prefixes ...string) []ContextProbe {
	if len(prefixes) > 0 && prefixes[0] != "" && prefixes[0] != analyze.MarkerPrefix {
		return buildProbeLibrary(prefixes[0])[ct]
	}
	return probeLibrary[ct]
}

/* probeLibrary maps each context type to its probe dimensions.
Probes are SAFE: no alert(), no side effects, just structural tests.
The first entry is the primary probe; additional entries test alternative
breakout mechanisms (e.g., quote breakout when angle brackets are stripped). */

var probeLibrary = buildProbeLibrary(analyze.MarkerPrefix)

func buildProbeLibrary(prefix string) map[ctx.ContextType][]ContextProbe {
	jsStringProbeValue := "';" + prefix + "//"
	jsonProbeValue := `"` + prefix + `"`
	templateLiteralProbeValue := "${" + prefix + "}"
	validateCommentBreakout := func(body string) bool { return strings.Contains(body, "<"+prefix+">") }
	validateAttrBreakout := func(body string) bool { return strings.Contains(body, prefix+">") }
	validateDoubleQuoteBreakout := func(body string) bool { return validateQuoteBreakoutWithPrefix(body, prefix) }
	validateSingleQuoteBreakout := validateDoubleQuoteBreakout
	validateJSONBreakout := func(body string) bool { return strings.Contains(body, jsonProbeValue) }
	return map[ctx.ContextType][]ContextProbe{
		ctx.ContextHTMLBody: {{
			ContextType: ctx.ContextHTMLBody,
			Probe:       "<" + prefix + ">",
			Validator:   validateUnescapedProbe("<" + prefix + ">"),
		}},
		ctx.ContextHTMLComment: {{
			ContextType: ctx.ContextHTMLComment,
			Probe:       "--><" + prefix + "><!--",
			Validator:   validateCommentBreakout,
		}},
		ctx.ContextHTMLTag: {{
			ContextType: ctx.ContextHTMLTag,
			Probe:       prefix,
			Validator:   validateUnescapedProbe(prefix),
		}},
		ctx.ContextHTMLAttrName: {{
			ContextType: ctx.ContextHTMLAttrName,
			Probe:       prefix,
			Validator:   validateUnescapedProbe(prefix),
		}},
		ctx.ContextHTMLAttrValue: {
			{
				ContextType: ctx.ContextHTMLAttrValue,
				Probe:       " " + prefix + ">",
				Validator:   validateAttrBreakout,
			},
			// Quote-only breakout: servers that strip < > but preserve quotes
			// are still exploitable via event-handler attribute injection
			// (" onmouseover=alert(1) x="). These probes validate that dimension.
			{
				ContextType: ctx.ContextHTMLAttrValue,
				Probe:       `" ` + prefix + `="`,
				Validator:   validateDoubleQuoteBreakout,
			},
			{
				ContextType: ctx.ContextHTMLAttrValue,
				Probe:       `' ` + prefix + `='`,
				Validator:   validateSingleQuoteBreakout,
			},
		},
		ctx.ContextHTMLEntity: {{
			ContextType: ctx.ContextHTMLEntity,
			Probe:       prefix,
			Validator:   validateUnescapedProbe(prefix),
		}},
		ctx.ContextJSString: {{
			ContextType: ctx.ContextJSString,
			Probe:       jsStringProbeValue,
			Validator:   validateUnescapedProbe(jsStringProbeValue),
		}},
		ctx.ContextJSComment: {{
			ContextType: ctx.ContextJSComment,
			Probe:       "/*" + prefix + "*/",
			Validator:   validateUnescapedProbe(prefix),
		}},
		ctx.ContextJSBlock: {{
			ContextType: ctx.ContextJSBlock,
			Probe:       "</script><" + prefix + ">",
			Validator:   validateUnescapedProbe("<" + prefix + ">"),
		}},
		ctx.ContextCSSValue: {{
			ContextType: ctx.ContextCSSValue,
			Probe:       prefix,
			Validator:   validateUnescapedProbe(prefix),
		}},
		ctx.ContextCSSBlock: {{
			ContextType: ctx.ContextCSSBlock,
			Probe:       "</style><" + prefix + "><style>",
			Validator:   validateUnescapedProbe("<" + prefix + ">"),
		}},
		ctx.ContextURLAttr: {{
			ContextType: ctx.ContextURLAttr,
			Probe:       "javascript:" + prefix,
			Validator:   validateURLBreakout,
		}},
		ctx.ContextTemplate: {{
			ContextType: ctx.ContextTemplate,
			Probe:       "{{" + prefix + "}}",
			Validator:   validateUnescapedProbe(prefix),
		}},
		ctx.ContextSVGContainer: {{
			ContextType: ctx.ContextSVGContainer,
			Probe:       "<" + prefix + ">",
			Validator:   validateUnescapedProbe("<" + prefix + ">"),
		}},
		ctx.ContextMathMLContainer: {{
			ContextType: ctx.ContextMathMLContainer,
			Probe:       "<" + prefix + ">",
			Validator:   validateUnescapedProbe("<" + prefix + ">"),
		}},
		ctx.ContextJSONValue: {{
			ContextType: ctx.ContextJSONValue,
			Probe:       jsonProbeValue,
			Validator:   validateJSONBreakout,
		}},
		ctx.ContextJSTemplateLiteral: {{
			ContextType: ctx.ContextJSTemplateLiteral,
			Probe:       templateLiteralProbeValue,
			Validator:   validateUnescapedProbe(templateLiteralProbeValue),
		}},
	}

}

/*
Probe values containing characters that are awkward to embed directly in Go
source (forward-slash sequences, single quotes, double quotes) are assembled
from runes at package init so the probe table stays readable.
*/

var (
	// jsStringProbeValue = ';xsscan// — breaks out of a single-quoted JS string.
	jsStringProbeValue = "';" + analyze.MarkerPrefix + "//"

	// jsonProbeValue = "xsscan" — breaks out of a JSON string value.
	jsonProbeValue = `"` + analyze.MarkerPrefix + `"`

	// templateLiteralProbeValue = ${xsscan} — tests expression breakout.
	templateLiteralProbeValue = "${" + analyze.MarkerPrefix + "}"
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
	return strings.Contains(body, "<"+analyze.MarkerPrefix+">")
}

/* validateAttrBreakout confirms the probe escaped the attribute value context. */

func validateAttrBreakout(body string) bool {
	return strings.Contains(body, analyze.MarkerPrefix+">")
}

/* validateQuoteBreakout confirms the probe's quote actually broke out of an
attribute value: the HTML tokenizer must find a tag attribute NAMED xsscan.
Naive substring checks produce false positives when quotes reflect raw in
body text (inert) or inside attribute values without breaking out. */

func validateQuoteBreakout(body string) bool {
	return validateQuoteBreakoutWithPrefix(body, analyze.MarkerPrefix)
}

func validateQuoteBreakoutWithPrefix(body, prefix string) bool {
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return false
		case html.StartTagToken, html.SelfClosingTagToken:
			// Read attributes from the current tag token.
			for {
				key, _, more := z.TagAttr()
				// HTML5 parses the injected quote as part of the attribute
				// name (parse error but tolerated): value=""xsscan"=" becomes
				// attribute `xsscan"`. Trim quotes before comparison.
				name := strings.Trim(string(key), `"'`)
				if strings.EqualFold(name, prefix) {
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
		for _, probe := range GetProbesForContext(c.Type, analyze.MarkerPrefixFromContext(stdctx)) {
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

func (e *Engine) sendProbeRequest(stdctx context.Context, injection model.InjectionPoint, probeValue, host string) (bodyText string, resultErr error) {
	o := e.observations.begin(injection, payload.Payload{Value: probeValue}, 0, "probe")
	trace, started := &attemptTrace{phase: failureBuild}, time.Now()
	stdctx = context.WithValue(stdctx, attemptTraceKey{}, trace)
	defer func() {
		finishAttempt(&o, trace, started, resultErr)
		e.observations.record(o)
		if resultErr != nil {
			e.recordRunError("probe", resultErr)
		}
	}()
	modifiedTarget, err := e.injectPayload(injection.Target, injection.Parameter, probeValue)
	if err != nil {
		return "", fmt.Errorf("probe inject: %w", err)
	}

	markAttemptPhase(stdctx, failurePolicy)
	if err := ssrfguard.IsURLTargetAllowedContext(stdctx, modifiedTarget.URL); err != nil {
		return "", fmt.Errorf("ssrf blocked: %w", err)
	}

	markAttemptPhase(stdctx, failureWait)
	if err := e.throttle.Wait(stdctx, host); err != nil {
		return "", err
	}

	markAttemptPhase(stdctx, failureBuild)
	req, err := e.buildRequest(stdctx, modifiedTarget)
	if err != nil {
		return "", err
	}

	markAttemptPhase(stdctx, failureTransport)
	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	markAttemptPhase(stdctx, failureRead)
	body, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
	captureAttemptResponse(&o, resp, body, probeValue)
	if err != nil {
		markAttemptReadError(stdctx)
		return "", err
	}

	markAttemptPhase(stdctx, failureStatus)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("probe HTTP %d", resp.StatusCode)
	}
	e.throttle.ReportSuccessHost(host)
	return string(body), nil
}
