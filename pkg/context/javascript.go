package context

import (
	"github.com/xsscan/xsscan/pkg/jsanalysis"
	"golang.org/x/net/html"
	"strings"
)

func jsContexts(source, value string, handler bool, offset int) []Context {
	a := jsanalysis.Parse(source, handler)
	var result []Context
	if value == "" {
		return result
	}
	for from := 0; from < len(source); {
		if len(result) >= 64 {
			result = append(result, Context{Type: ContextUnknown, AnalysisMethod: "goja-ast", ParseError: "JavaScript reflection occurrence analysis limit exceeded"})
			break
		}
		i := strings.Index(source[from:], value)
		if i < 0 {
			break
		}
		i += from
		s := a.At(i)
		c := Context{AnalysisMethod: "goja-ast", ParseError: a.Error, SourceStart: offset + i, SourceEnd: offset + i + len(value), SpanUnit: "document_bytes", QuoteChar: s.Quote, Raw: source[max(0, i-50):min(len(source), i+len(value)+50)]}
		if handler {
			c.SpanUnit = "attribute_value_bytes"
		}
		switch s.Kind {
		case jsanalysis.String:
			c.Type = ContextJSString
			c.Enclosed = true
		case jsanalysis.Template:
			c.Type = ContextJSTemplateLiteral
			c.Enclosed = true
		case jsanalysis.Comment:
			c.Type = ContextJSComment
		case jsanalysis.Regexp:
			c.Type = ContextJSRegexp
			c.Enclosed = true
		case jsanalysis.Code:
			c.Type = ContextJSBlock
		default:
			c.Type = ContextUnknown
		}
		result = append(result, c)
		from = i + len(value)
	}
	return result
}

func executableScriptRaw(raw string) bool {
	t := html.NewTokenizer(strings.NewReader(raw))
	t.Next()
	token := t.Token()
	for _, a := range token.Attr {
		if a.Key == "src" {
			return false
		}
		if a.Key == "type" {
			switch strings.ToLower(strings.TrimSpace(a.Val)) {
			case "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript":
			default:
				return false
			}
		}
	}
	return true
}
