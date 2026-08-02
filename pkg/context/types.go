package context

import "strings"

type ContextType int

const (
	ContextUnknown       ContextType = iota
	ContextHTMLBody                  // <div>PAYLOAD</div>
	ContextHTMLComment               // <!-- PAYLOAD -->
	ContextHTMLTag                   // <PAYLOAD>
	ContextHTMLAttrName              // <tag PAYLOAD="value">
	ContextHTMLAttrValue             // <tag attr="PAYLOAD">
	ContextHTMLEntity                // &PAYLOAD;
	ContextJSString                  // var x = 'PAYLOAD'
	ContextJSComment                 // // PAYLOAD
	ContextJSBlock                   // <script>PAYLOAD</script>
	ContextCSSValue                  // color: PAYLOAD
	ContextCSSBlock                  // <style>PAYLOAD</style>
	ContextURLAttr                   // <a href="PAYLOAD">
	ContextTemplate                  // {{ PAYLOAD }}
	ContextSVGContainer              // <svg>PAYLOAD</svg>
	ContextMathMLContainer           // <math>PAYLOAD</math>
	ContextJSONValue                 // {"key": "PAYLOAD"} — JSON string value
	ContextJSTemplateLiteral         // var x = `PAYLOAD` — JS template literal (backtick)
	ContextMulti                     // Multiple contexts
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
	default:
		return ContextUnknown
	}
}

type Context struct {
	Type        ContextType `json:"type"`
	TagName     string      `json:"tag_name,omitempty"`
	AttrName    string      `json:"attr_name,omitempty"`
	Enclosed    bool        `json:"enclosed"`
	QuoteChar   string      `json:"quote_char"`
	Escaped     bool        `json:"escaped"`
	Encoded     []string    `json:"encoded"`
	ParentStack []string    `json:"parent_stack"`
	Raw         string      `json:"raw"`
	Priority    int         `json:"priority"`
}

// IsExploitableType reports whether a context type can potentially execute
// scripts (ignoring escape status). This is the single source of truth for
// context exploitability classification.
func (c ContextType) IsExploitableType() bool {
	switch c {
	case ContextHTMLBody, ContextHTMLTag, ContextHTMLAttrName,
		ContextHTMLAttrValue, ContextJSString, ContextJSTemplateLiteral,
		ContextJSBlock, ContextURLAttr, ContextTemplate,
		ContextSVGContainer, ContextMathMLContainer,
		ContextJSONValue:
		return true
	}
	return false
}

func (c *Context) IsExploitable() bool {
	return c.Type.IsExploitableType() && !c.Escaped
}
