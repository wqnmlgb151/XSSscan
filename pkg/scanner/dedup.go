package scanner

import (
	"regexp"
	"strings"

	"github.com/xsscan/xsscan/pkg/model"
)

// attackVectorClass represents the broad category of an XSS attack technique.
// Findings with the same class at the same parameter/context are semantically
// equivalent — different payloads within the same class are just variations.
type attackVectorClass string

const (
	VectorTagInjection   attackVectorClass = "tag_injection"    // <script>, <img>, <svg>, etc.
	VectorEventHandler   attackVectorClass = "event_handler"    // onerror, onload, onfocus, etc.
	VectorJSBreakout     attackVectorClass = "js_breakout"      // ';alert(1)// etc.
	VectorAttrBreakout   attackVectorClass = "attr_breakout"    // "><img, '><svg, etc.
	VectorTemplateInject attackVectorClass = "template_inject"  // {{ }}, ${ }, etc.
	VectorCommentBreakout attackVectorClass = "comment_breakout" // -->, /* */
	VectorURIInjection   attackVectorClass = "uri_injection"    // javascript:, data:, vbscript:
	VectorCSSInjection   attackVectorClass = "css_injection"    // expression(), url(javascript:)
	VectorUnknown        attackVectorClass = "unknown"
)

// contextClass represents the execution capability of a reflection context.
type contextClass string

const (
	ContextHTMLExecute  contextClass = "html_execute"  // HTML body, tag, attr — script can run
	ContextJSExecute    contextClass = "js_execute"    // JS string, block, template — JS can run
	ContextBreakout     contextClass = "breakout"      // Attr value, comment, entity — need breakout first
	ContextURL          contextClass = "url"           // URL attribute — javascript: protocol
	ContextLimited      contextClass = "limited"       // CSS, entity — limited execution
)

// payloadPatterns for attack vector classification.
var payloadPatterns = []struct {
	class   attackVectorClass
	pattern *regexp.Regexp
}{
	// Order matters: more specific patterns first
	{VectorAttrBreakout, regexp.MustCompile(`^['"]?>\s*<\w`)},              // "><img, '><svg — attribute breakout
	{VectorJSBreakout, regexp.MustCompile(`^['";\s]['"]?[-;]`)},             // ';alert(1)// — JS context breakout
	{VectorCommentBreakout, regexp.MustCompile(`-->|/\*`)},                  // HTML/JS comment breakout
	{VectorTagInjection, regexp.MustCompile(`(?i)^<\s*(script|img|svg|details|math|body|iframe|object|embed|video|audio|source|marquee|link|base|meta|style)`)},
	{VectorEventHandler, regexp.MustCompile(`(?i)\bon\w+\s*=`)},              // onerror=, onload=, etc.
	{VectorTemplateInject, regexp.MustCompile(`\{\{.*\}\}|\$\{.*\}`)},       // {{ }}, ${ }
	{VectorURIInjection, regexp.MustCompile(`(?i)^(javascript|data|vbscript|blob|filesystem):`)},
	{VectorCSSInjection, regexp.MustCompile(`(?i)(expression\s*\(|url\s*\(\s*['"]?javascript)`)},
}

// contextClassification maps context types to execution capability classes.
var contextClassification = map[string]contextClass{
	"html_body":           ContextHTMLExecute,
	"html_tag":            ContextHTMLExecute,
	"html_attr_name":      ContextHTMLExecute,
	"html_attr_value":     ContextBreakout,
	"html_comment":        ContextBreakout,
	"html_entity":         ContextLimited,
	"js_string":           ContextJSExecute,
	"js_comment":          ContextJSExecute,
	"js_block":            ContextJSExecute,
	"js_template_literal": ContextJSExecute,
	"css_value":           ContextLimited,
	"css_block":           ContextLimited,
	"url_attribute":       ContextURL,
	"template":            ContextJSExecute,
	"svg_container":       ContextHTMLExecute,
	"mathml_container":    ContextHTMLExecute,
	"json_value":          ContextBreakout,
}

// classifyAttackVector determines the attack technique category from a payload.
func classifyAttackVector(payload string) attackVectorClass {
	trimmed := strings.TrimSpace(payload)
	for _, p := range payloadPatterns {
		if p.pattern.MatchString(trimmed) {
			return p.class
		}
	}
	return VectorUnknown
}

// classifyContext maps a context type string to its execution capability class.
func classifyContext(context string) contextClass {
	if c, ok := contextClassification[context]; ok {
		return c
	}
	return ContextLimited
}

// primaryContextClass returns the highest-capability context class from a list.
func primaryContextClass(contexts []string) contextClass {
	best := ContextLimited
	priority := map[contextClass]int{
		ContextHTMLExecute: 5,
		ContextJSExecute:   4,
		ContextURL:         3,
		ContextBreakout:    2,
		ContextLimited:     1,
	}
	for _, c := range contexts {
		cl := classifyContext(c)
		if priority[cl] > priority[best] {
			best = cl
		}
	}
	return best
}

// dedupKey represents the semantic identity of a finding for deduplication.
type dedupKey struct {
	url          string
	param        string
	contextClass string
	vectorClass  string
}

// SemanticDedup performs deduplication keeping the highest-confidence finding
// per semantic key (URL + parameter + context class + attack vector class).
// This replaces crude prefix-based dedup with semantic understanding.
func SemanticDedup(findings []model.Finding) []model.Finding {
	seen := make(map[dedupKey]*model.Finding)

	for i := range findings {
		f := &findings[i]

		key := dedupKey{
			url:          f.URL,
			param:        f.Parameter,
			contextClass: string(primaryContextClass(f.Contexts)),
			vectorClass:  string(classifyAttackVector(f.Payload)),
		}

		if existing, ok := seen[key]; ok {
			// Keep the higher-confidence finding
			if f.Confidence > existing.Confidence {
				seen[key] = f
			}
			// If same confidence but verified, prefer verified
			if f.Confidence == existing.Confidence && f.ExecutionVerified && !existing.ExecutionVerified {
				seen[key] = f
			}
		} else {
			seen[key] = f
		}
	}

	result := make([]model.Finding, 0, len(seen))
	for _, f := range seen {
		result = append(result, *f)
	}
	return result
}
