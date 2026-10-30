package context

import (
	"strconv"
	"strings"
)

type ContextType int

const (
	ContextUnknown           ContextType = iota
	ContextHTMLBody                      // <div>PAYLOAD</div>
	ContextHTMLComment                   // <!-- PAYLOAD -->
	ContextHTMLTag                       // <PAYLOAD>
	ContextHTMLAttrName                  // <tag PAYLOAD="value">
	ContextHTMLAttrValue                 // <tag attr="PAYLOAD">
	ContextHTMLEntity                    // &PAYLOAD;
	ContextJSString                      // var x = 'PAYLOAD'
	ContextJSComment                     // // PAYLOAD
	ContextJSBlock                       // <script>PAYLOAD</script>
	ContextCSSValue                      // color: PAYLOAD
	ContextCSSBlock                      // <style>PAYLOAD</style>
	ContextURLAttr                       // <a href="PAYLOAD">
	ContextTemplate                      // {{ PAYLOAD }}
	ContextSVGContainer                  // <svg>PAYLOAD</svg>
	ContextMathMLContainer               // <math>PAYLOAD</math>
	ContextJSONValue                     // {"key": "PAYLOAD"} — JSON string value
	ContextJSTemplateLiteral             // var x = `PAYLOAD` — JS template literal (backtick)
	ContextMulti                         // Multiple contexts
	ContextJSRegexp                      // /PAYLOAD/ — regex literal, not division
)

func (c ContextType) String() string {
	switch c {
	case ContextHTMLBody:
		return "html_body"
	case ContextHTMLComment:
		return "html_comment"
	case ContextHTMLTag:
		return "html_tag"
	case ContextHTMLAttrName:
		return "html_attr_name"
	case ContextHTMLAttrValue:
		return "html_attr_value"
	case ContextHTMLEntity:
		return "html_entity"
	case ContextJSString:
		return "js_string"
	case ContextJSComment:
		return "js_comment"
	case ContextJSBlock:
		return "js_block"
	case ContextCSSValue:
		return "css_value"
	case ContextCSSBlock:
		return "css_block"
	case ContextURLAttr:
		return "url_attribute"
	case ContextTemplate:
		return "template"
	case ContextSVGContainer:
		return "svg_container"
	case ContextMathMLContainer:
		return "mathml_container"
	case ContextJSONValue:
		return "json_value"
	case ContextJSTemplateLiteral:
		return "js_template_literal"
	case ContextMulti:
		return "multi"
	case ContextJSRegexp:
		return "js_regexp"
	default:
		return "unknown"
	}
}

func ParseContextType(s string) ContextType {
	switch strings.ToLower(s) {
	case "html_body":
		return ContextHTMLBody
	case "html_comment":
		return ContextHTMLComment
	case "html_tag":
		return ContextHTMLTag
	case "html_attr_name":
		return ContextHTMLAttrName
	case "html_attr_value":
		return ContextHTMLAttrValue
	case "html_entity":
		return ContextHTMLEntity
	case "js_string":
		return ContextJSString
	case "js_comment":
		return ContextJSComment
	case "js_block":
		return ContextJSBlock
	case "css_value":
		return ContextCSSValue
	case "css_block":
		return ContextCSSBlock
	case "url_attribute":
		return ContextURLAttr
	case "template":
		return ContextTemplate
	case "svg_container":
		return ContextSVGContainer
	case "mathml_container":
		return ContextMathMLContainer
	case "json_value":
		return ContextJSONValue
	case "js_template_literal":
		return ContextJSTemplateLiteral
	case "multi":
		return ContextMulti
	case "js_regexp":
		return ContextJSRegexp
	default:
		return ContextUnknown
	}
}

// Context describes one classified reflection. Two anchors are kept because
// they answer different questions and neither substitutes for the other:
//
//   - SourceStart/SourceEnd/SpanUnit locate the reflection inside the analyzed
//     *script* source (or attribute value). They are only populated for the
//     JavaScript and event-handler paths and are empty for HTML contexts.
//   - ReflectionAt/ReflectionUnit locate the reflection inside the whole
//     *response document*, which is what makes a reflection occurrence
//     individually addressable regardless of context family.
//
// ReflectionAt is a byte offset into the response that produced this context.
// It is stable only while that document's preceding bytes stay unchanged, so
// callers must treat it as a locating hint for one response, never as an
// identity that survives a re-fetch (see Context.ReflectionKey).
type Context struct {
	AnalysisMethod string      `json:"analysis_method,omitempty"`
	ParseError     string      `json:"parse_error,omitempty"`
	SourceStart    int         `json:"source_start,omitempty"`
	SourceEnd      int         `json:"source_end,omitempty"`
	SpanUnit       string      `json:"span_unit,omitempty"`
	ReflectionAt   int         `json:"reflection_at,omitempty"`
	ReflectionUnit string      `json:"reflection_unit,omitempty"`
	Type           ContextType `json:"type"`
	TagName        string      `json:"tag_name,omitempty"`
	AttrName       string      `json:"attr_name,omitempty"`
	Enclosed       bool        `json:"enclosed"`
	QuoteChar      string      `json:"quote_char"`
	Escaped        bool        `json:"escaped"`
	Encoded        []string    `json:"encoded"`
	ParentStack    []string    `json:"parent_stack"`
	Raw            string      `json:"raw"`
	Priority       int         `json:"priority"`
}

// ReflectionKey returns a stable, comparable string identifying this one
// reflection position for the response it was detected in. It is the unit a
// scheduler may reason about: two payloads whose reflections produce the same
// key are competing for the same position, while different keys are
// independent positions and must not be collapsed into one decision.
//
// Composition is deliberate, per the dynamic-scheduling plan:
//   - Type and QuoteChar distinguish an HTML body reflection from a
//     single-quoted attribute reflection in the same document.
//   - TagName/AttrName distinguish two attributes of the same tag.
//   - ReflectionAt is the occurrence offset, NOT a cross-response identity: it
//     only separates several reflections in one response. Callers must re-derive
//     the key from each new response instead of caching it across fetches.
//
// The returned string is empty when the context carries no usable anchor. That
// is the conservative case, not a safe one — an unanchored context must never
// be used to conclude that other positions are covered.
func (c Context) ReflectionKey() string {
	if c.ReflectionUnit == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(c.ReflectionUnit)
	b.WriteByte('|')
	b.WriteString(c.Type.String())
	b.WriteByte('@')
	b.WriteString(strconv.Itoa(c.ReflectionAt))
	if c.TagName != "" {
		b.WriteString("|tag=")
		b.WriteString(strings.ToLower(c.TagName))
	}
	if c.AttrName != "" {
		b.WriteString("|attr=")
		b.WriteString(strings.ToLower(c.AttrName))
	}
	if c.QuoteChar != "" {
		b.WriteString("|q=")
		b.WriteString(c.QuoteChar)
	}
	return b.String()
}

// IsExploitableType reports whether a context type can potentially execute
// scripts (ignoring escape status). This is the single source of truth for
// context exploitability classification.
func (c ContextType) IsExploitableType() bool {
	switch c {
	case ContextHTMLBody, ContextHTMLTag, ContextHTMLAttrName,
		ContextHTMLAttrValue, ContextJSString, ContextJSTemplateLiteral,
		ContextJSBlock, ContextJSComment, ContextJSRegexp, ContextURLAttr, ContextTemplate,
		ContextSVGContainer, ContextMathMLContainer,
		ContextJSONValue:
		return true
	}
	return false
}

func (c *Context) IsExploitable() bool {
	return c.Type.IsExploitableType() && !c.Escaped
}
