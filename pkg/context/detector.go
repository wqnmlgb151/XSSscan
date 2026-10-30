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
	eventAttrRe *regexp.Regexp
}

// NewDetector creates a new Detector with pre-compiled regexes
func NewDetector() *Detector {
	return &Detector{
		templateRe:  regexp.MustCompile(`\{\{(.*?)\}\}`),
		angularRe:   regexp.MustCompile(`\[([a-zA-Z-]+)\]\s*=\s*["']([^"']*)["']`),
		eventAttrRe: xsspatterns.EventHandlerAttrRe,
	}
}

// Detect runs a single HTML tokenizer pass to classify all contexts.
//
// One pass classifies every reflection occurrence in the document, which is why
// a single call returns contexts for several positions at once: the JavaScript
// path reports one context per occurrence, and the HTML path one per matching
// token. Each context therefore anchors itself at the site that produced it.
//
// The loop below only fills in an anchor for contexts whose classification
// cannot know its own position (raw-text bodies, malformed markup). They fall
// back to the reflection offset the caller searched for, marked "response_bytes"
// so a fallback anchor is never mistaken for a located one.
func (d *Detector) Detect(ref Reflection) ([]Context, error) {
	contexts := d.detectAll(ref)
	for i := range contexts {
		if contexts[i].ReflectionUnit == "" {
			contexts[i].ReflectionAt = ref.Offset
			contexts[i].ReflectionUnit = "response_bytes"
		}
	}
	return contexts, nil
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
	var scriptExecutable bool
	var scriptModule bool
	position := 0
	var inRawText bool
	var parentStack []string

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		start := position
		position += len(tokenizer.Raw())

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			// TagAttr decodes entities in place, so preserve raw delimiters first.
			rawTag := string(tokenizer.Raw())
			tagName, hasAttr := tokenizer.TagName()
			name := string(tagName)
			// TAG NAME injection: <MARKER>content</MARKER> — marker reflected
			// in the element name itself. The tokenizer lowercases tag names
			// and markers are lowercase (GenerateMarker), so plain Contains
			// suffices — no ToLower needed on the hot path.
			if strings.Contains(name, value) {
				contexts = append(contexts, Context{
					Type:         ContextHTMLTag,
					TagName:      name,
					Raw:          text.Snippet(name, value, 50),
					Enclosed:     true,
					ParentStack:  copyStack(parentStack),
					ReflectionAt: start,
				})
			}
			switch name {
			case "script":
				inScript = true
				scriptExecutable = executableScriptRaw(string(tokenizer.Raw()))
				scriptModule = moduleScriptRaw(string(tokenizer.Raw()))
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
				d.detectAttrContexts(tokenizer, tagStartPos{start: start, raw: rawTag}, name, value, parentStack, &contexts, attributeDelimiters(rawTag))
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
				if inScript && scriptExecutable && !inRawText {
					for _, c := range jsContexts(txt, value, false, start, scriptModule) {
						c.ParentStack = copyStack(parentStack)
						contexts = append(contexts, c)
					}
					continue
				}
				ctx := Context{Raw: text.Snippet(txt, value, 50), ParentStack: copyStack(parentStack), ReflectionAt: start + strings.Index(txt, value)}
				switch {
				case inRawText:
					// Raw-text elements (textarea, title, xmp, etc.) — content is inert
					ctx.Type = ContextHTMLEntity
					ctx.Escaped = true
				case inScript:
					ctx.Type = ContextHTMLEntity
					ctx.Escaped = true
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
					Type:         ContextHTMLComment,
					Raw:          text.Snippet(comment, value, 50),
					ParentStack:  copyStack(parentStack),
					ReflectionAt: start + strings.Index(comment, value),
				})
			}
		}
	}

	d.detectTemplateContext(content, value, &contexts)
	return rankContexts(contexts)
}

// tagStartPos carries where the current start tag begins in the response and
// its raw bytes. Attribute values are located relative to that raw tag, which
// yields an exact document offset instead of a whole-tag approximation.
type tagStartPos struct {
	start int
	raw   string
}

// locate returns the document offset of needle within the raw tag, preferring
// the occurrence at or after fromRaw (a raw-tag-relative hint), and falling
// back to the first occurrence. found reports whether the needle was located
// at all; callers must treat false as "anchor unknown", never as offset 0.
func (p tagStartPos) locate(needle string, fromRaw int) (offset int, found bool) {
	if needle == "" || p.raw == "" {
		return 0, false
	}
	if fromRaw >= 0 && fromRaw < len(p.raw) {
		if i := strings.Index(p.raw[fromRaw:], needle); i >= 0 {
			return p.start + fromRaw + i, true
		}
	}
	if i := strings.Index(p.raw, needle); i >= 0 {
		return p.start + i, true
	}
	return 0, false
}

func (d *Detector) detectAttrContexts(tokenizer *html.Tokenizer, tag tagStartPos, tagName, value string, parentStack []string, contexts *[]Context, delimiters []attributeDelimiter) {
	index := 0
	rawCursor := 0
	for {
		var key, val []byte
		key, val, _ = tokenizer.TagAttr()
		if key == nil {
			break
		}
		attrName := string(key)
		attrVal := string(val)
		quote := ""
		if index < len(delimiters) && delimiters[index].name == attrName {
			quote = delimiters[index].quote
		}
		// Advance a raw-tag cursor past the attribute name so that repeated
		// values resolve to the attribute actually being examined rather than
		// to an earlier identically-valued attribute.
		nameAt := rawCursor
		if i := strings.Index(tag.raw[rawCursor:], attrName); i >= 0 {
			nameAt = rawCursor + i
			rawCursor = nameAt + len(attrName)
		}
		index++
		// Attribute NAME injection: marker reflected in the attribute name
		// itself (<div MARKER=...>) — exploitable via on* event injection.
		// The tokenizer lowercases attribute names and markers are lowercase
		// (GenerateMarker), so plain Contains suffices.
		if strings.Contains(attrName, value) {
			ctx := Context{
				Type:        ContextHTMLAttrName,
				TagName:     tagName,
				AttrName:    attrName,
				Raw:         text.Snippet(attrName, value, 50),
				Enclosed:    true,
				ParentStack: copyStack(parentStack),
			}
			if at, ok := tag.locate(attrName, nameAt); ok {
				ctx.ReflectionAt = at + strings.Index(attrName, value)
			}
			*contexts = append(*contexts, ctx)
			continue
		}
		if strings.Contains(attrVal, value) {
			// The value itself follows the name; locate it forward from there.
			valAt, valFound := tag.locate(attrVal, nameAt+len(attrName))
			ctxType := ContextHTMLAttrValue
			switch {
			case d.eventAttrRe.MatchString(attrName):
				// Event handlers are JS execution contexts. Analyze the
				// attribute value for JS sub-context: onclick="foo('PAYLOAD')"
				// is a JS STRING (quote breakout needed), while
				// onclick="alert(PAYLOAD)" is a JS BLOCK (direct execution).
				// XSStrike-style sub-context analysis.
				for _, sub := range jsContexts(attrVal, value, true, 0) {
					sub.TagName = tagName
					sub.AttrName = attrName
					sub.ParentStack = copyStack(parentStack)
					// In handler mode the parser only sees the attribute VALUE,
					// so SourceStart is value-relative. Translate it into a
					// document offset and keep the value-relative span intact —
					// the span is script evidence, ReflectionAt is the anchor.
					if valFound {
						sub.ReflectionAt = valAt + sub.SourceStart
					}
					*contexts = append(*contexts, sub)
				}
				continue
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
				QuoteChar:   quote,
				TagName:     tagName,
				AttrName:    attrName,
				Raw:         text.Snippet(attrVal, value, 50),
				Enclosed:    true,
				ParentStack: copyStack(parentStack),
			}
			if valFound {
				ctx.ReflectionAt = valAt + strings.Index(attrVal, value)
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

func (d *Detector) detectTemplateContext(content, value string, contexts *[]Context) {
	// FindAllStringSubmatchIndex (not ...Submatch) because a template reflection
	// needs its document offset: two {{...}} blocks in one page are different
	// injection positions, and only the offset tells them apart.
	for _, m := range d.templateRe.FindAllStringSubmatchIndex(content, -1) {
		if len(m) < 4 || m[2] < 0 {
			continue
		}
		inner := content[m[2]:m[3]]
		if strings.Contains(inner, value) {
			ctx := Context{
				Type: ContextTemplate,
				Raw:  text.Snippet(inner, value, 50),
			}
			if i := strings.Index(inner, value); i >= 0 {
				ctx.ReflectionAt = m[2] + i
			}
			*contexts = append(*contexts, ctx)
		}
	}
	for _, m := range d.angularRe.FindAllStringSubmatchIndex(content, -1) {
		if len(m) < 6 || m[4] < 0 {
			continue
		}
		attrVal := content[m[4]:m[5]]
		if strings.Contains(attrVal, value) {
			ctx := Context{
				Type:     ContextTemplate,
				AttrName: content[m[2]:m[3]],
				Raw:      text.Snippet(attrVal, value, 50),
			}
			if i := strings.Index(attrVal, value); i >= 0 {
				ctx.ReflectionAt = m[4] + i
			}
			*contexts = append(*contexts, ctx)
		}
	}
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
