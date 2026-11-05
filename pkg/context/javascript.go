package context

import (
	"github.com/wqnmlgb151/XSSscan/pkg/jsanalysis"
	"golang.org/x/net/html"
	"strings"
)

func jsContexts(source, value string, handler bool, offset int, module ...bool) []Context {
	var result []Context
	if value == "" || !strings.Contains(source, value) {
		return result
	}
	mode := jsanalysis.ScriptMode
	if handler {
		mode = jsanalysis.HandlerMode
	} else if len(module) > 0 && module[0] {
		mode = jsanalysis.ModuleMode
	}
	a := jsanalysis.ParseWithMode(source, mode)
	for from := 0; from < len(source); {
		if len(result) >= 64 {
			result = append(result, Context{Type: ContextUnknown, AnalysisMethod: jsanalysis.Method, ParseError: "JavaScript reflection occurrence analysis limit exceeded"})
			break
		}
		i := strings.Index(source[from:], value)
		if i < 0 {
			break
		}
		i += from
		s := a.At(i)
		c := Context{
			AnalysisMethod: jsanalysis.Method,
			ParseError:     a.Error,
			SourceStart:    offset + i,
			SourceEnd:      offset + i + len(value),
			SpanUnit:       "document_bytes",
			// SourceStart is already an absolute offset into the response
			// document, so it doubles as the reflection anchor here.
			ReflectionAt:   offset + i,
			ReflectionUnit: "document_bytes",
			QuoteChar:      s.Quote,
			Raw:            source[max(0, i-50):min(len(source), i+len(value)+50)],
		}
		if handler {
			c.SpanUnit = "attribute_value_bytes"
			// Only the attribute value was parsed, so SourceStart is relative to
			// that value and cannot anchor a position in the whole document.
			c.ReflectionAt, c.ReflectionUnit = 0, ""
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

func moduleScriptRaw(raw string) bool {
	t := html.NewTokenizer(strings.NewReader(raw))
	t.Next()
	for _, a := range t.Token().Attr {
		if a.Key == "type" {
			return strings.EqualFold(strings.TrimSpace(a.Val), "module")
		}
	}
	return false
}
