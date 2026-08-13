package scanner

import (
	"regexp"
	"strings"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/internal/urlutil"
	"github.com/xsscan/xsscan/pkg/model"
)

// attackVectorClass represents the broad category of an XSS attack technique.
// Findings with the same class at the same parameter/context are semantically
// equivalent — different payloads within the same class are just variations.
type attackVectorClass string

const (
	VectorTagInjection    attackVectorClass = "tag_injection"    // <script>, <img>, <svg>, etc.
	VectorEventHandler    attackVectorClass = "event_handler"    // onerror, onload, onfocus, etc.
	VectorJSBreakout      attackVectorClass = "js_breakout"      // ';alert(1)// etc.
	VectorAttrBreakout    attackVectorClass = "attr_breakout"    // "><img, '><svg, etc.
	VectorTemplateInject  attackVectorClass = "template_inject"  // {{ }}, ${ }, etc.
	VectorCommentBreakout attackVectorClass = "comment_breakout" // -->, /* */
	VectorURIInjection    attackVectorClass = "uri_injection"    // javascript:, data:, vbscript:
	VectorCSSInjection    attackVectorClass = "css_injection"    // expression(), url(javascript:)
	VectorUnknown         attackVectorClass = "unknown"
)

// contextClass represents the execution capability of a reflection context.
type contextClass string

const (
	ContextHTMLExecute contextClass = "html_execute" // HTML body, tag, attr — script can run
	ContextJSExecute   contextClass = "js_execute"   // JS string, block, template — JS can run
	ContextBreakout    contextClass = "breakout"     // Attr value, comment, entity — need breakout first
	ContextURL         contextClass = "url"          // URL attribute — javascript: protocol
	ContextLimited     contextClass = "limited"      // CSS, entity — limited execution
)

// payloadPatterns for attack vector classification.
var payloadPatterns = []struct {
	class   attackVectorClass
	pattern *regexp.Regexp
}{
	// Order matters: more specific patterns first
	{VectorAttrBreakout, regexp.MustCompile(`^['"]?>\s*<\w`)},   // "><img, '><svg — attribute breakout
	{VectorJSBreakout, regexp.MustCompile(`^['";\s]['"]?[-;]`)}, // ';alert(1)// — JS context breakout
	{VectorCommentBreakout, regexp.MustCompile(`-->|/\*`)},      // HTML/JS comment breakout
	{VectorTagInjection, regexp.MustCompile(`(?i)^<\s*(script|img|svg|details|math|body|iframe|object|embed|video|audio|source|marquee|link|base|meta|style)`)},
	{VectorEventHandler, regexp.MustCompile(`(?i)\bon\w+\s*=`)},       // onerror=, onload=, etc.
	{VectorTemplateInject, regexp.MustCompile(`\{\{.*\}\}|\$\{.*\}`)}, // {{ }}, ${ }
	{VectorURIInjection, regexp.MustCompile(`(?i)^(javascript|data|vbscript|blob|filesystem):`)},
	{VectorCSSInjection, regexp.MustCompile(`(?i)(expression\s*\(|url\s*\(\s*['"]?javascript)`)},
}

// contextClassification maps context types to execution capability classes.
var eventHandlerRe = regexp.MustCompile(`(?i)\bon\w+\s*=|\bon\w+\s*:`)

var contextPriority = map[contextClass]int{
	ContextHTMLExecute: 5,
	ContextJSExecute:   4,
	ContextURL:         3,
	ContextBreakout:    2,
	ContextLimited:     1,
}

var contextClassification = map[ctx.ContextType]contextClass{
	ctx.ContextHTMLBody:          ContextHTMLExecute,
	ctx.ContextHTMLTag:           ContextHTMLExecute,
	ctx.ContextHTMLAttrName:      ContextHTMLExecute,
	ctx.ContextHTMLAttrValue:     ContextBreakout,
	ctx.ContextHTMLComment:       ContextBreakout,
	ctx.ContextHTMLEntity:        ContextLimited,
	ctx.ContextJSString:          ContextJSExecute,
	ctx.ContextJSComment:         ContextJSExecute,
	ctx.ContextJSBlock:           ContextJSExecute,
	ctx.ContextJSTemplateLiteral: ContextJSExecute,
	ctx.ContextCSSValue:          ContextLimited,
	ctx.ContextCSSBlock:          ContextLimited,
	ctx.ContextURLAttr:           ContextURL,
	ctx.ContextTemplate:          ContextJSExecute,
	ctx.ContextSVGContainer:      ContextHTMLExecute,
	ctx.ContextMathMLContainer:   ContextHTMLExecute,
	ctx.ContextJSONValue:         ContextBreakout,
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

// parseContextTypes converts string context names to typed ContextType values.
func parseContextTypes(contexts []string) []ctx.ContextType {
	result := make([]ctx.ContextType, 0, len(contexts))
	for _, s := range contexts {
		ct := ctx.ParseContextType(s)
		if ct != ctx.ContextUnknown {
			result = append(result, ct)
		}
	}
	return result
}

// classifyContext maps a context type to its execution capability class.
func classifyContext(ct ctx.ContextType) contextClass {
	if c, ok := contextClassification[ct]; ok {
		return c
	}
	return ContextLimited
}

// primaryContextClass returns the highest-capability context class from a list.
func primaryContextClass(contexts []ctx.ContextType) contextClass {
	best := ContextLimited
	for _, c := range contexts {
		cl := classifyContext(c)
		if contextPriority[cl] > contextPriority[best] {
			best = cl
		}
	}
	return best
}

// exploitClass categorizes the technical mechanism used by a payload.
// Unlike attackVectorClass (which detects the broad attack surface: tag, event, URI),
// exploitClass groups payloads by the specific technique, enabling finer dedup.
type exploitClass string

const (
	ExploitScriptTag   exploitClass = "script"   // <script>, <svg><script>, </script><script>
	ExploitEventHandle exploitClass = "event"    // onerror, onload, onfocus, ontoggle, etc.
	ExploitProtocol    exploitClass = "protocol" // javascript:, data:, vbscript:
	ExploitNestedExec  exploitClass = "nested"   // srcdoc, annotation-xml, foreignObject
	ExploitBreakout    exploitClass = "breakout" // </textarea>, </title>, -->, close-tag breakout
	ExploitImport      exploitClass = "import"   // <link import, @import, <base href=
	ExploitMetaRefresh exploitClass = "meta"     // <meta refresh, CSP bypass via meta
	ExploitOther       exploitClass = "other"
)

// classifyExploit determines the specific technical mechanism of a payload.
func classifyExploit(payload string) exploitClass {
	p := strings.TrimSpace(payload)

	// Breakout payloads start with closing tags or comment terminators
	if strings.HasPrefix(p, "</") || strings.HasPrefix(p, "-->") || strings.HasPrefix(p, "*/") {
		return ExploitBreakout
	}

	lower := strings.ToLower(p)

	// Nested execution contexts — check before protocol, since srcdoc payloads
	// can also contain javascript: strings
	if strings.Contains(lower, "srcdoc") || strings.Contains(lower, "annotation-xml") ||
		strings.Contains(lower, "foreignobject") {
		return ExploitNestedExec
	}

	// Script tags — check before protocol for mixed script+URI payloads
	if strings.Contains(lower, "<script") {
		return ExploitScriptTag
	}

	// Protocol-based execution — only classify as protocol if it's NOT already
	// an event-handler payload (event handlers take precedence)
	if strings.Contains(lower, "javascript:") || strings.Contains(lower, "data:") || strings.Contains(lower, "vbscript:") {
		if !eventHandlerRe.MatchString(p) {
			return ExploitProtocol
		}
	}

	// Meta/refresh
	if strings.Contains(lower, "<meta ") || strings.Contains(lower, "http-equiv") {
		return ExploitMetaRefresh
	}

	// Import/link/base
	if strings.Contains(lower, "<link ") || strings.Contains(lower, "@import") || strings.Contains(lower, "<base ") {
		return ExploitImport
	}

	// Event handlers — use precompiled package-level regex
	if eventHandlerRe.MatchString(p) {
		return ExploitEventHandle
	}

	return ExploitOther
}

// dedupKey represents the semantic identity of a finding for deduplication.
// normalizeURL strips query and fragment for dedup comparison,
// so payload-specific URL encoding doesn't create unique keys per payload.
type dedupKey struct {
	baseURL      string
	param        string
	contextClass string
	vectorClass  string
	exploitClass string
}

// SemanticDedup performs deduplication keeping the highest-confidence finding
// per semantic key (URL + parameter + context + vector + exploit class).
// The exploitClass differentiates payloads using different technical mechanisms
// even when they share the same broad attack vector — reducing noise from
// "49 findings" to ~5 exploit variants.
func SemanticDedup(findings []model.Finding) []model.Finding {
	seen := make(map[dedupKey]*model.Finding)
	var order []dedupKey

	for i := range findings {
		f := &findings[i]

		key := dedupKey{
			baseURL:      urlutil.NormalizeForDedup(f.URL),
			param:        f.Parameter,
			contextClass: string(primaryContextClass(parseContextTypes(f.Contexts))),
			vectorClass:  string(classifyAttackVector(f.Payload)),
			exploitClass: string(classifyExploit(f.Payload)),
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
			order = append(order, key) // preserve first-seen order for deterministic output
		}
	}

	result := make([]model.Finding, 0, len(order))
	for _, key := range order {
		result = append(result, *seen[key])
	}
	return result
}
