// Package jsanalysis parses target JavaScript without executing it.
package jsanalysis

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

const MaxSourceBytes = 256 * 1024
const maxNodes = 100000
const maxNesting = 256

type Kind string

const (
	Code     Kind = "code"
	String   Kind = "string"
	Template Kind = "template"
	Comment  Kind = "comment"
	Regexp   Kind = "regexp"
	Unknown  Kind = "unknown"
)

type Span struct {
	Start, End int
	Kind       Kind
	Quote      string
}
type Analysis struct {
	Spans []Span
	Calls []Span
	Error string
}

// Parse uses a function-body wrapper for event handlers (where return is legal).
// AST indices are converted back to byte offsets in the original source.
func Parse(source string, handler bool) (out Analysis) {
	defer func() {
		if r := recover(); r != nil {
			out = Analysis{Error: fmt.Sprintf("JavaScript parser panic: %v", r)}
		}
	}()
	if len(source) > MaxSourceBytes {
		out.Error = "JavaScript source exceeds 256 KiB analysis limit"
		return
	}
	// Bound recursive parser work before invoking a parser that has no cancellation
	// API. This deliberately also counts delimiters in literals; exceeding the
	// conservative budget is unknown, never evidence of valid syntax.
	depth := 0
	operators, questions, unaryRun := 0, 0, 0
	for _, r := range source {
		if strings.ContainsRune("=?!~+-*/%&|^", r) {
			operators++
		}
		if r == '?' {
			questions++
		}
		if r == '!' || r == '~' || r == '+' || r == '-' {
			unaryRun++
		} else if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			unaryRun = 0
		}
		if operators > 4096 || questions > 256 || unaryRun > 256 {
			out.Error = "JavaScript operator complexity exceeds analysis limit"
			return
		}
		switch r {
		case '(', '[', '{':
			depth++
			if depth > maxNesting {
				out.Error = "JavaScript nesting exceeds analysis limit"
				return
			}
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	parsed, shift := source, 0
	if handler {
		prefix := "function __xsscan_handler__(){\n"
		parsed = prefix + source + "\n}"
		shift = len(prefix)
	}
	program, err := parser.ParseFile(nil, "", parsed, 0, parser.WithDisableSourceMaps)
	if err != nil {
		out.Error = err.Error()
		return
	}
	stack := []reflect.Value{reflect.ValueOf(program)}
	seen := make(map[uintptr]bool)
	nodes := 0
	add := func(start, end int, kind Kind, quote string, call bool) {
		start -= shift
		end -= shift
		if start < 0 || end > len(source) || start >= end {
			return
		}
		s := Span{start, end, kind, quote}
		if call {
			out.Calls = append(out.Calls, s)
		} else {
			out.Spans = append(out.Spans, s)
		}
	}
	for len(stack) > 0 {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		nodes++
		if nodes > maxNodes {
			return Analysis{Error: "JavaScript AST exceeds analysis limit"}
		}
		if v.Kind() == reflect.Interface {
			if !v.IsNil() {
				stack = append(stack, v.Elem())
			}
			continue
		}
		if v.Kind() == reflect.Pointer {
			if v.IsNil() || seen[v.Pointer()] {
				continue
			}
			seen[v.Pointer()] = true
			if v.CanInterface() {
				switch n := v.Interface().(type) {
				case *ast.StringLiteral:
					add(int(n.Idx0())-1, int(n.Idx1())-1, String, parsed[int(n.Idx0())-1:int(n.Idx0())], false)
				case *ast.RegExpLiteral:
					add(int(n.Idx0())-1, int(n.Idx1())-1, Regexp, "/", false)
				case *ast.TemplateElement:
					// Goja records TemplateElement.Idx after the first source rune.
					// Resolve its raw literal span, including multibyte first runes.
					endFirst := int(n.Idx0()) - 1
					_, width := utf8.DecodeLastRuneInString(parsed[:endFirst])
					start := endFirst - width
					if n.Literal != "" {
						if start < 0 || start+len(n.Literal) > len(parsed) || parsed[start:start+len(n.Literal)] != n.Literal {
							return Analysis{Error: "JavaScript template source span could not be resolved"}
						}
						add(start, start+len(n.Literal), Template, "`", false)
					}
				case *ast.CallExpression:
					add(int(n.Idx0())-1, int(n.Idx1())-1, Code, "", true)
				case *ast.TemplateLiteral:
					if n.Tag != nil {
						add(int(n.Tag.Idx0())-1, int(n.CloseQuote), Code, "", true)
					}
				case *ast.NewExpression:
					add(int(n.Idx0())-1, int(n.Idx1())-1, Code, "", true)
				}
			}
			// Walk only AST objects, never file metadata or arbitrary interface data.
			if v.Elem().Kind() == reflect.Struct && v.Elem().Type().PkgPath() == "github.com/dop251/goja/ast" {
				stack = append(stack, v.Elem())
			}
			continue
		}
		if v.Kind() == reflect.Struct {
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).PkgPath == "" {
					stack = append(stack, v.Field(i))
				}
			}
		}
		if v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				stack = append(stack, v.Index(i))
			}
		}
	}
	sort.Slice(out.Spans, func(i, j int) bool { return out.Spans[i].Start < out.Spans[j].Start })
	// Comments are not AST nodes. Scan gaps between parsed literal spans so // in
	// a string, template quasi or regexp is never mistaken for a comment.
	protected := 0
	for i := 0; i < len(source); {
		for protected < len(out.Spans) && out.Spans[protected].End <= i {
			protected++
		}
		if protected < len(out.Spans) && out.Spans[protected].Start <= i {
			i = out.Spans[protected].End
			continue
		}
		if strings.HasPrefix(source[i:], "//") {
			end := strings.IndexAny(source[i:], "\r\n\u2028\u2029")
			if end < 0 {
				end = len(source) - i
			}
			out.Spans = append(out.Spans, Span{i, i + end, Comment, "//"})
			i += end
			continue
		}
		if strings.HasPrefix(source[i:], "/*") {
			end := strings.Index(source[i+2:], "*/")
			if end < 0 {
				return Analysis{Error: "unterminated JavaScript comment"}
			}
			end += i + 4
			out.Spans = append(out.Spans, Span{i, end, Comment, "/*"})
			i = end
			continue
		}
		i++
	}
	return
}

// At classifies a source occurrence. Parse failure stays unknown.
func (a Analysis) At(offset int) Span {
	if a.Error != "" {
		return Span{offset, offset, Unknown, ""}
	}
	for _, s := range a.Spans {
		if s.Start <= offset && offset < s.End {
			return s
		}
	}
	return Span{offset, offset + 1, Code, ""}
}

// HasCallStartingIn proves an AST call originates inside this candidate span.
// It is structural evidence only: branches/functions may never execute.
func (a Analysis) HasCallStartingIn(start, end int) bool {
	if a.Error != "" {
		return false
	}
	for _, c := range a.Calls {
		if c.Start >= start && c.Start < end {
			return true
		}
	}
	return false
}
