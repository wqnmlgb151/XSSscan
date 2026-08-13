package context

import (
	"regexp"
	"sort"
	"strings"

	"github.com/xsscan/xsscan/pkg/internal/text"
	"github.com/xsscan/xsscan/pkg/internal/xsspatterns"
	"golang.org/x/net/html"
)

// Reflection holds data needed to detect injection context
type Reflection struct {
	Content    string
	Offset     int
	ParamValue string
	StatusCode int
}

// Detector analyzes reflection points to determine injection context
type Detector struct {
	templateRe  *regexp.Regexp
	angularRe   *regexp.Regexp
	scriptRe    *regexp.Regexp
	eventAttrRe *regexp.Regexp
}

// NewDetector creates a new Detector with pre-compiled regexes
func NewDetector() *Detector {
	return &Detector{
		templateRe:  regexp.MustCompile(`\{\{(.*?)\}\}`),
		angularRe:   regexp.MustCompile(`\[([a-zA-Z-]+)\]\s*=\s*["']([^"']*)["']`),
		scriptRe:    regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`),
		eventAttrRe: xsspatterns.EventHandlerAttrRe,
	}
}

// Detect runs a single HTML tokenizer pass to classify all contexts
func (d *Detector) Detect(ref Reflection) ([]Context, error) {
	return d.detectAll(ref), nil
}

// rawTextElements are HTML elements whose content is not parsed as HTML.
// Reflection inside these elements cannot execute scripts.
var rawTextElements = map[string]bool{
	"textarea": true, "title": true, "xmp": true,
	"iframe": true, "noscript": true, "noframes": true,
	"plaintext": true,
}

// voidElements are HTML5 tags that never have closing tags.
// They must NOT be pushed onto the parent stack since they
// never pop, corrupting context detection for subsequent siblings.
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true,
	"embed": true, "hr": true, "img": true, "input": true,
	"link": true, "meta": true, "param": true, "source": true,
	"track": true, "wbr": true,
}

func (d *Detector) detectAll(ref Reflection) []Context {
	var contexts []Context
	content := ref.Content
	value := ref.ParamValue

	tokenizer := html.NewTokenizer(strings.NewReader(content))
	var inScript, inStyle, inSVG, inMath bool
	var inRawText bool
	var parentStack []string

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tagName, hasAttr := tokenizer.TagName()
			name := string(tagName)
			// TAG NAME injection: <MARKER>content</MARKER> — marker reflected
			// in the element name itself. The tokenizer lowercases tag names
			// and markers are lowercase (GenerateMarker), so plain Contains
			// suffices — no ToLower needed on the hot path.
			if strings.Contains(name, value) {
				contexts = append(contexts, Context{
					Type:        ContextHTMLTag,
					TagName:     name,
					Raw:         text.Snippet(name, value, 50),
					Enclosed:    true,
					ParentStack: copyStack(parentStack),
				})
			}
			switch name {
			case "script":
				inScript = true
			case "style":
				inStyle = true
			case "svg":
				inSVG = true
			case "math":
				inMath = true
			}
			if rawTextElements[name] {
				inRawText = true
			}
			if hasAttr {
				d.detectAttrContexts(tokenizer, name, value, parentStack, &contexts)
			}
			// Only push non-void elements onto the parent stack.
			// Void elements (<img>, <br>, <input>, etc.) never generate
			// EndTagToken and would corrupt sibling context detection.
			if !voidElements[name] {
				parentStack = append(parentStack, name)
			}
		case html.EndTagToken:
			tagName, _ := tokenizer.TagName()
			name := string(tagName)
			switch name {
			case "script":
				inScript = false
			case "style":
				inStyle = false
			case "svg":
				inSVG = false
			case "math":
				inMath = false
			}
			if rawTextElements[name] {
				inRawText = false
			}
			if len(parentStack) > 0 {
				parentStack = parentStack[:len(parentStack)-1]
			}
		case html.TextToken:
			if txt := string(tokenizer.Text()); strings.Contains(txt, value) {
				ctx := Context{Raw: text.Snippet(txt, value, 50), ParentStack: copyStack(parentStack)}
				switch {
				case inRawText:
					// Raw-text elements (textarea, title, xmp, etc.) — content is inert
					ctx.Type = ContextHTMLEntity
					ctx.Escaped = true
				case inScript:
					ctx.Type = ContextJSBlock
				case inStyle:
					ctx.Type = ContextCSSBlock
				case inSVG:
					ctx.Type = ContextSVGContainer
				case inMath:
					ctx.Type = ContextMathMLContainer
				default:
					ctx.Type = ContextHTMLBody
				}
				contexts = append(contexts, ctx)
			}
		case html.CommentToken:
			if comment := string(tokenizer.Text()); strings.Contains(comment, value) {
				contexts = append(contexts, Context{
					Type:        ContextHTMLComment,
					Raw:         text.Snippet(comment, value, 50),
					ParentStack: copyStack(parentStack),
				})
			}
		}
	}

	d.detectJSStringContext(content, value, &contexts)
	d.detectTemplateContext(content, value, &contexts)
	return rankContexts(contexts)
}

func (d *Detector) detectAttrContexts(tokenizer *html.Tokenizer, tagName, value string, parentStack []string, contexts *[]Context) {
	for {
		var key, val []byte
		key, val, _ = tokenizer.TagAttr()
		if key == nil {
			break
		}
		attrName := string(key)
		attrVal := string(val)
		// Attribute NAME injection: marker reflected in the attribute name
		// itself (<div MARKER=...>) — exploitable via on* event injection.
		// The tokenizer lowercases attribute names and markers are lowercase
		// (GenerateMarker), so plain Contains suffices.
		if strings.Contains(attrName, value) {
			*contexts = append(*contexts, Context{
				Type:        ContextHTMLAttrName,
				TagName:     tagName,
				AttrName:    attrName,
				Raw:         text.Snippet(attrName, value, 50),
				Enclosed:    true,
				ParentStack: copyStack(parentStack),
			})
			continue
		}
		if strings.Contains(attrVal, value) {
			ctxType := ContextHTMLAttrValue
			switch {
			case d.eventAttrRe.MatchString(attrName):
				// Event handlers are JS execution contexts. Analyze the
				// attribute value for JS sub-context: onclick="foo('PAYLOAD')"
				// is a JS STRING (quote breakout needed), while
				// onclick="alert(PAYLOAD)" is a JS BLOCK (direct execution).
				// XSStrike-style sub-context analysis.
				sub := analyzeJSStringContext(attrVal, value)
				ctxType = sub.Type
			case attrName == "style":
				ctxType = ContextCSSValue
			case attrName == "href" || attrName == "src" ||
				attrName == "action" || attrName == "formaction":
				// URL sub-context: scheme injection only works at the start
				// of the attribute value (or after an app-emitted scheme).
				ctxType = analyzeURLContext(attrVal, value)
			}
			ctx := Context{
				Type:        ctxType,
				TagName:     tagName,
				AttrName:    attrName,
				Raw:         text.Snippet(attrVal, value, 50),
				Enclosed:    true,
				ParentStack: copyStack(parentStack),
			}
			// ContextHTMLEntity is non-exploitable by type (IsExploitableType);
			// Escaped only zeroes the ranking priority so the inert context
			// never outranks a real exploitable reflection of the same param.
			if ctxType == ContextHTMLEntity {
				ctx.Escaped = true
			}
			*contexts = append(*contexts, ctx)
		}
	}
}

// analyzeURLContext classifies a reflection inside a URL attribute
// (href/src/action). Scheme injection only works when the reflection lands
// at the very start of the attribute value, or after a scheme the app
// already emitted. The allowlist is exact: a javascript: prefix executes;
// a data: prefix executes only for content types that render markup
// (image/svg+xml / text/html — a png data URL cannot run script). Anything
// else — path/query/fragment positions (xsf02.swf?arg=MARKER) or opaque
// schemes (http:, mailto:) — is inert because the scheme cannot change.
func analyzeURLContext(attrVal, value string) ContextType {
	idx := strings.Index(attrVal, value)
	if idx < 0 {
		return ContextURLAttr
	}
	prefix := strings.ToLower(attrVal[:idx])
	switch {
	case prefix == "":
		return ContextURLAttr // attribute start — full scheme injection
	case strings.HasPrefix(prefix, "javascript:"):
		return ContextURLAttr // app already emitted an executable scheme
	case strings.HasPrefix(prefix, "data:image/svg+xml,"),
		strings.HasPrefix(prefix, "data:text/html,"):
		return ContextURLAttr // executable data: content type
	}
	return ContextHTMLEntity // inert: path/query/fragment/opaque scheme
}

func (d *Detector) detectJSStringContext(content, value string, contexts *[]Context) {
	for _, s := range d.scriptRe.FindAllStringSubmatch(content, -1) {
		scriptBody := s[1]
		if !strings.Contains(scriptBody, value) {
			continue
		}
		ctx := analyzeJSStringContext(scriptBody, value)
		ctx.Raw = text.Snippet(scriptBody, value, 50)
		*contexts = append(*contexts, ctx)
	}
}

func (d *Detector) detectTemplateContext(content, value string, contexts *[]Context) {
	for _, m := range d.templateRe.FindAllStringSubmatch(content, -1) {
		if strings.Contains(m[1], value) {
			*contexts = append(*contexts, Context{
				Type: ContextTemplate,
				Raw:  text.Snippet(m[1], value, 50),
			})
		}
	}
	for _, m := range d.angularRe.FindAllStringSubmatch(content, -1) {
		if strings.Contains(m[2], value) {
			*contexts = append(*contexts, Context{
				Type:     ContextTemplate,
				AttrName: m[1],
				Raw:      text.Snippet(m[2], value, 50),
			})
		}
	}
}

func analyzeJSStringContext(script, value string) Context {
	idx := strings.Index(script, value)
	if idx < 0 {
		return Context{Type: ContextJSBlock}
	}
	before := script[:idx]

	// Use proper unescaped counting instead of naive strings.Count
	sq := countUnescaped(before, '\'')
	dq := countUnescaped(before, '"')
	bt := countUnescapedBacktick(before)

	switch {
	case sq%2 == 1:
		return Context{Type: ContextJSString, Enclosed: true, QuoteChar: "'"}
	case dq%2 == 1:
		return Context{Type: ContextJSString, Enclosed: true, QuoteChar: `"`}
	case bt%2 == 1:
		return Context{Type: ContextJSTemplateLiteral, Enclosed: true, QuoteChar: "`"}
	}
	lastNewline := strings.LastIndex(before, "\n")
	if lastNewline < 0 {
		lastNewline = 0
	}
	if strings.Contains(before[lastNewline:], "//") {
		return Context{Type: ContextJSComment}
	}
	if strings.Count(before, "/*") > strings.Count(before, "*/") {
		return Context{Type: ContextJSComment}
	}
	return Context{Type: ContextJSBlock}
}

// countUnescaped counts occurrences of target rune that are NOT preceded by a backslash.
func countUnescaped(s string, target rune) int {
	count := 0
	escaped := false
	for _, c := range s {
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == target {
			count++
		}
	}
	return count
}

// countUnescapedBacktick counts backticks not preceded by backslash, excluding
// backticks inside ${...} template expressions (simplified: counts nesting depth).
func countUnescapedBacktick(s string) int {
	count := 0
	escaped := false
	depth := 0
	for _, c := range s {
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '$' && depth == 0 {
			continue
		}
		if c == '{' && depth < 1 {
			depth++
			continue
		}
		if c == '}' && depth > 0 {
			depth--
			continue
		}
		if c == '`' && depth == 0 {
			count++
		}
	}
	return count
}

func rankContexts(ctxs []Context) []Context {
	for i := range ctxs {
		ctxs[i].Priority = calculatePriority(ctxs[i])
	}
	sort.Slice(ctxs, func(i, j int) bool {
		return ctxs[i].Priority > ctxs[j].Priority
	})
	return ctxs
}

func calculatePriority(c Context) int {
	if c.Escaped {
		return 0
	}
	switch c.Type {
	case ContextHTMLBody:
		return 100
	case ContextHTMLAttrValue:
		return 90
	case ContextJSString:
		return 85
	case ContextURLAttr:
		return 80
	case ContextTemplate:
		return 75
	case ContextJSBlock:
		return 70
	case ContextSVGContainer:
		return 65
	case ContextMathMLContainer:
		return 65
	case ContextHTMLTag:
		return 60
	case ContextCSSValue:
		return 40
	default:
		return 10
	}
}

func copyStack(stack []string) []string {
	if len(stack) == 0 {
		return nil
	}
	newStack := make([]string, len(stack))
	copy(newStack, stack)
	return newStack
}
