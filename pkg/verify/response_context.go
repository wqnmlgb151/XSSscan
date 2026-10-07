package verify

import (
	"regexp"
	"strings"

	"github.com/xsscan/xsscan/pkg/analyze"
	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/internal/xsspatterns"
	"github.com/xsscan/xsscan/pkg/payload"
	"golang.org/x/net/html"
)

type reflectionSpan struct{ start, end int }

// Bound fallback parsing of ambiguous reflections in an untrusted response.
// Tokenizer-proven inert reflections never consume this budget.
const maxContextChecks = 64

var urlAttributeAssignRe = regexp.MustCompile(`(?i)\b(?:xlink:href|href|srcdoc|src|action|formaction|data)\s*=`)

// responseContext checks the returned document rather than trusting a template's
// context. Token offsets tie newly created executable markup to the payload;
// substituting a marker recovers the surrounding context for non-markup payloads.
func (v *Verifier) responseContext(body string, p payload.Payload) (ctx.ContextType, bool) {
	return v.responseContextAtDepth(body, p, 0)
}

func (v *Verifier) responseContextAtDepth(body string, p payload.Payload, depth int) (ctx.ContextType, bool) {
	if depth >= 8 {
		return ctx.ContextUnknown, false
	}
	var spans []reflectionSpan
	for offset := 0; offset < len(body); {
		i := strings.Index(body[offset:], p.Value)
		if i < 0 {
			break
		}
		start := offset + i
		spans = append(spans, reflectionSpan{start, start + len(p.Value)})
		offset = start + len(p.Value)
	}
	if len(spans) == 0 {
		return ctx.ContextUnknown, false
	}
	// Tokenize once to find structural breakouts and non-executable script data.
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	position, spanIndex := 0, 0
	inertSpans := make([]bool, len(spans))
	inScript, scriptExecutable := false, false
	rawTextElement, templateDepth := "", 0
	marker := analyze.GenerateMarker()
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		raw := string(tokenizer.Raw())
		start, end := position, position+len(raw)
		position = end
		token := tokenizer.Token()
		if tt == html.StartTagToken {
			if token.Data == "template" {
				templateDepth++
			}
			switch token.Data {
			case "textarea", "title", "xmp", "iframe", "noscript", "noframes", "plaintext":
				rawTextElement = token.Data
			}
		}
		if tt == html.StartTagToken && token.Data == "script" {
			inScript, scriptExecutable = true, executableScript(token) && !scriptHasSource(token)
		}
		for spanIndex < len(spans) && spans[spanIndex].end <= start {
			spanIndex++
		}
		for j := spanIndex; j < len(spans) && spans[j].start < end; j++ {
			span := spans[j]
			if span.start >= start && span.end <= end && (tt == html.CommentToken || templateDepth > 0 ||
				(tt == html.TextToken && (rawTextElement != "" || (inScript && !scriptExecutable)))) {
				inertSpans[j] = true
			}
			if tt == html.TextToken && !inScript && span.start >= start && span.end <= end {
				switch p.Context {
				case ctx.ContextJSBlock, ctx.ContextJSString, ctx.ContextJSTemplateLiteral,
					ctx.ContextURLAttr, ctx.ContextHTMLAttrName, ctx.ContextHTMLAttrValue:
					inertSpans[j] = true
				}
			}
			if templateDepth == 0 && (tt == html.StartTagToken || tt == html.SelfClosingTagToken) {
				if token.Data == "script" && executableScript(token) && start >= span.start && start < span.end {
					return ctx.ContextJSBlock, true
				}
				seenAttrs := make(map[string]bool)
				for _, attr := range token.Attr {
					if seenAttrs[attr.Key] {
						continue
					}
					seenAttrs[attr.Key] = true
					srcdocExecutable := false
					if token.Data == "iframe" && attr.Key == "srcdoc" && attr.Val != "" {
						_, srcdocExecutable = v.responseContextAtDepth(attr.Val, payload.Payload{Value: attr.Val, Context: ctx.ContextHTMLBody}, depth+1)
					}
					if executableURLAttribute(attr) || srcdocExecutable {
						// Prove the attribute was created by this payload, rather
						// than an unrelated executable URL elsewhere in the tag.
						for _, match := range urlAttributeAssignRe.FindAllStringIndex(raw, -1) {
							name := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw[match[0]:match[1]], "=")))
							if name == attr.Key && start+match[0] >= span.start && start+match[0] < span.end && attributeNameAt(raw, attr.Key, match[0], marker) {
								if srcdocExecutable {
									return ctx.ContextHTMLBody, true
								}
								return ctx.ContextURLAttr, true
							}
						}
					}
					if !xsspatterns.EventHandlerAttrRe.MatchString(attr.Key) || attr.Val == "" {
						continue
					}
					for _, match := range xsspatterns.EventHandlerAssignRe.FindAllStringIndex(raw, -1) {
						assignment := strings.ToLower(raw[match[0]:match[1]])
						if strings.HasPrefix(assignment, attr.Key) && start+match[0] >= span.start && start+match[0] < span.end &&
							attributeNameAt(raw, attr.Key, match[0], marker) {
							return ctx.ContextJSBlock, true
						}
					}
				}
			}
		}
		if tt == html.EndTagToken && token.Data == "script" {
			inScript = false
		}
		if tt == html.EndTagToken {
			if token.Data == rawTextElement {
				rawTextElement = ""
			}
			if token.Data == "template" && templateDepth > 0 {
				templateDepth--
			}
		}
	}
	checks := 0
	for i, span := range spans {
		if inertSpans[i] {
			continue
		}
		if checks >= maxContextChecks {
			break
		}
		checks++
		marked := body[:span.start] + contextMarker(p, marker) + body[span.end:]
		contexts, err := v.detector.Detect(ctx.Reflection{Content: marked, Offset: span.start, ParamValue: marker})
		if err != nil {
			continue
		}
		// The detector's supplementary regexes may see a script/template inside
		// textarea or comments. Tokenizer evidence of inert text takes precedence.
		inert, jsLiteral, jsContext := false, false, false
		for _, c := range contexts {
			for _, parent := range c.ParentStack {
				if parent == "template" {
					inert = true
				}
			}
			if c.Type == ctx.ContextJSString || c.Type == ctx.ContextJSTemplateLiteral {
				jsLiteral = true
			}
			if c.Type == ctx.ContextJSBlock || c.Type == ctx.ContextJSString || c.Type == ctx.ContextJSTemplateLiteral {
				jsContext = true
			}
			if !c.Type.IsExploitableType() {
				inert = true
				break
			}
		}
		if inert {
			continue
		}
		for _, c := range contexts {
			if c.Type == ctx.ContextTemplate && jsContext {
				continue
			}
			if c.Type == ctx.ContextJSBlock && jsLiteral {
				continue
			}
			if !c.IsExploitable() || !responseContextCompatible(p, c) {
				continue
			}
			return c.Type, true
		}
	}
	return ctx.ContextUnknown, false
}

// attributeNameAt uses the tokenizer to distinguish an actual attribute name
// from assignment-looking text in another attribute's value. Only the first
// occurrence of a duplicate attribute can affect browser behavior.
func attributeNameAt(raw, name string, offset int, marker string) bool {
	marked := raw[:offset] + marker + raw[offset+len(name):]
	t := html.NewTokenizer(strings.NewReader(marked))
	if tt := t.Next(); tt != html.StartTagToken && tt != html.SelfClosingTagToken {
		return false
	}
	for _, attr := range t.Token().Attr {
		if attr.Key == name {
			return false
		}
		if attr.Key == marker {
			return true
		}
	}
	return false
}

func contextMarker(p payload.Payload, marker string) string {
	// Keep framework delimiters: removing {{...}} would discard the very
	// context under test. The surrounding HTML is still independently checked.
	if p.Context == ctx.ContextTemplate {
		start, end := strings.Index(p.Value, "{{"), strings.LastIndex(p.Value, "}}")
		if start >= 0 && end >= start+2 {
			return p.Value[:start+2] + marker + p.Value[end:]
		}
	}
	return marker
}

func responseContextCompatible(p payload.Payload, actual ctx.Context) bool {
	if actual.Type != p.Context {
		return false
	}
	if actual.Type == ctx.ContextJSString {
		return payload.QuoteCompatible(p.Value, actual.Type, actual.QuoteChar)
	}
	if actual.Type == ctx.ContextHTMLBody && strings.Contains(p.Value, "<") {
		// Markup payloads require an actual parsed executable sink. Replacing
		// a whole inert element with a marker would otherwise look like body text.
		return false
	}
	if actual.Type == ctx.ContextHTMLAttrName || actual.Type == ctx.ContextHTMLAttrValue {
		// Attribute injection requires an effective executable attribute or
		// markup breakout, checked by the structural pass above.
		return false
	}
	return true
}

func executableURLAttribute(attr html.Attribute) bool {
	switch attr.Key {
	case "href", "xlink:href", "src", "action", "formaction", "data":
		value := strings.ToLower(strings.TrimSpace(attr.Val))
		return strings.HasPrefix(value, "javascript:") || strings.HasPrefix(value, "data:text/html,") || strings.HasPrefix(value, "data:image/svg+xml,")
	}
	return false
}

func executableScript(token html.Token) bool {
	for _, attr := range token.Attr {
		if attr.Key == "type" {
			switch strings.ToLower(strings.TrimSpace(attr.Val)) {
			case "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript":
				return true
			default:
				return false
			}
		}
	}
	return true
}

func scriptHasSource(token html.Token) bool {
	for _, attr := range token.Attr {
		if attr.Key == "src" {
			return true
		}
	}
	return false
}
