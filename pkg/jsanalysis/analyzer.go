// Package jsanalysis parses target JavaScript without executing it.
package jsanalysis

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/grafana/sobek/ast"
	"github.com/grafana/sobek/parser"
	"github.com/grafana/sobek/token"
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
	Flows []Flow
	// FlowError records work limits/ambiguity, not an exhaustive coverage claim.
	// Unsupported flow constructs may yield no hints; callers must keep fallback checks.
	FlowError string
}

const Method = "sobek-ast"

type SourceMode uint8

const (
	ScriptMode SourceMode = iota
	HandlerMode
	ModuleMode
)

// Parse uses a function-body wrapper for event handlers (where return is legal).
// AST indices are converted back to byte offsets in the original source.
func Parse(source string, handler bool) Analysis {
	mode := ScriptMode
	if handler {
		mode = HandlerMode
	}
	return ParseWithMode(source, mode)
}

func ParseWithMode(source string, mode SourceMode) Analysis {
	if len(source) > MaxSourceBytes {
		return Analysis{Error: "JavaScript source exceeds 256 KiB analysis limit"}
	}
	if mode > ModuleMode {
		return Analysis{Error: "invalid JavaScript source mode"}
	}
	return parsedScripts.parse(source, mode)
}

func parseUncached(source string, mode SourceMode) (out Analysis) {
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
	if mode == HandlerMode {
		prefix := "function __xsscan_handler__(){\n"
		parsed = prefix + source + "\n}"
		shift = len(prefix)
	}
	options := []parser.Option{parser.WithDisableSourceMaps}
	if mode == ModuleMode {
		options = append(options, parser.IsModule)
	}
	program, err := parser.ParseFile(nil, "", parsed, 0, options...)
	if err != nil {
		out.Error = err.Error()
		return
	}
	type visit struct {
		value reflect.Value
		live  bool
	}
	stack := []visit{{reflect.ValueOf(program), true}}
	seen := make(map[uintptr]uint8)
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
		item := stack[len(stack)-1]
		v, live := item.value, item.live
		stack = stack[:len(stack)-1]
		nodes++
		if nodes > maxNodes {
			return Analysis{Error: "JavaScript AST exceeds analysis limit"}
		}
		if v.Kind() == reflect.Interface {
			if !v.IsNil() {
				stack = append(stack, visit{v.Elem(), live})
			}
			continue
		}
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				continue
			}
			if v.CanInterface() {
				switch v.Interface().(type) {
				case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
					// Callers and declaration hoisting are not resolved here.
					live = true
				}
			}
			flag := uint8(1)
			if live {
				flag = 2
			}
			previous := seen[v.Pointer()]
			if previous&flag != 0 || previous&2 != 0 {
				continue
			}
			seen[v.Pointer()] = previous | flag
			if v.CanInterface() {
				switch n := v.Interface().(type) {
				case *ast.StringLiteral:
					quote := "'"
					if parsed[int(n.Idx0())-1] == '"' {
						quote = `"`
					}
					add(int(n.Idx0())-1, int(n.Idx1())-1, String, quote, false)
				case *ast.RegExpLiteral:
					add(int(n.Idx0())-1, int(n.Idx1())-1, Regexp, "/", false)
				case *ast.TemplateElement:
					// Sobek records TemplateElement.Idx after the first source rune.
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
					if live {
						add(int(n.Idx0())-1, int(n.Idx1())-1, Code, "", true)
					}
				case *ast.TemplateLiteral:
					if live && n.Tag != nil {
						add(int(n.Tag.Idx0())-1, int(n.CloseQuote), Code, "", true)
					}
				case *ast.NewExpression:
					if live {
						add(int(n.Idx0())-1, int(n.Idx1())-1, Code, "", true)
					}
				}
			}
			// Walk only AST objects, never file metadata or arbitrary interface data.
			if v.Elem().Kind() == reflect.Struct && v.Elem().Type().PkgPath() == "github.com/grafana/sobek/ast" {
				stack = append(stack, visit{v.Elem(), live})
			}
			continue
		}
		if v.Kind() == reflect.Struct {
			deadField := deadBranchField(v)
			for i := 0; i < v.NumField(); i++ {
				field := v.Type().Field(i)
				// DeclarationList aliases bindings in statements. Traversing the
				// scope metadata would attribute dead initializers to live scope.
				if field.PkgPath == "" && field.Name != "DeclarationList" {
					childLive := live && field.Name != deadField
					stack = append(stack, visit{v.Field(i), childLive})
				}
			}
		}
		if v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				stack = append(stack, visit{v.Index(i), live})
			}
		}
	}
	if problem := validateSyntax(parsed, mode); problem != "" {
		return Analysis{Error: problem}
	}
	out.Flows, out.FlowError = analyzeFlows(program, shift, len(source))
	sort.Slice(out.Spans, func(i, j int) bool { return out.Spans[i].Start < out.Spans[j].Start })
	// Comments are not AST nodes. Scan gaps between parsed literal spans so // in
	// a string, template quasi or regexp is never mistaken for a comment.
	protected := 0
	literals := out.Spans
	for i := 0; i < len(source); {
		for protected < len(literals) && literals[protected].End <= i {
			protected++
		}
		if protected < len(literals) && literals[protected].Start <= i {
			i = literals[protected].End
			continue
		}
		if strings.HasPrefix(source[i:], "//") || (i == 0 && strings.HasPrefix(source, "#!")) ||
			(mode != ModuleMode && (strings.HasPrefix(source[i:], "<!--") || (strings.HasPrefix(source[i:], "-->") && atLineStart(source, i)))) {
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
		// Module specifiers and quoted import/export names are validated by
		// Sobek, but its AST stores their decoded value without a source span.
		// Recover lexical string spans only after a successful full parse.
		if mode == ModuleMode && (source[i] == '\'' || source[i] == '"') {
			quote, start := source[i], i
			closed := false
			i++
			for i < len(source) {
				if source[i] == '\\' {
					i += 2
					continue
				}
				if source[i] == quote {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed || i > len(source) {
				return Analysis{Error: "JavaScript string span could not be resolved"}
			}
			out.Spans = append(out.Spans, Span{start, i, String, string(quote)})
			continue
		}
		i++
	}
	sort.Slice(out.Spans, func(i, j int) bool { return out.Spans[i].Start < out.Spans[j].Start })
	sort.Slice(out.Calls, func(i, j int) bool { return out.Calls[i].Start < out.Calls[j].Start })
	return
}

// Only literal booleans establish unreachable branches. Keep all literal spans
// and validate the entire program, including unreachable syntax. Unknown tests
// and function bodies remain potential execution evidence.
func deadBranchField(v reflect.Value) string {
	var test ast.Expression
	switch n := v.Addr().Interface().(type) {
	case *ast.IfStatement:
		test = n.Test
	case *ast.ConditionalExpression:
		test = n.Test
	case *ast.WhileStatement:
		if b, ok := n.Test.(*ast.BooleanLiteral); ok && !b.Value {
			return "Body"
		}
		return ""
	case *ast.BinaryExpression:
		b, ok := n.Left.(*ast.BooleanLiteral)
		if ok && (n.Operator == token.LOGICAL_AND && !b.Value || n.Operator == token.LOGICAL_OR && b.Value) {
			return "Right"
		}
		return ""
	default:
		return ""
	}
	b, ok := test.(*ast.BooleanLiteral)
	if !ok {
		return ""
	}
	if b.Value {
		return "Alternate"
	}
	return "Consequent"
}

func atLineStart(source string, offset int) bool {
	for offset > 0 {
		r, width := utf8.DecodeLastRuneInString(source[:offset])
		if strings.ContainsRune("\r\n\u2028\u2029", r) {
			return true
		}
		if !unicode.IsSpace(r) && r != '\uFEFF' {
			return false
		}
		offset -= width
	}
	return true
}

// At classifies a source occurrence. Parse failure stays unknown.
func (a Analysis) At(offset int) Span {
	if a.Error != "" {
		return Span{offset, offset, Unknown, ""}
	}
	i := sort.Search(len(a.Spans), func(i int) bool { return a.Spans[i].Start > offset }) - 1
	if i >= 0 && offset < a.Spans[i].End {
		return a.Spans[i]
	}
	return Span{offset, offset + 1, Code, ""}
}

// HasCallStartingIn proves an AST call originates inside this candidate span.
// It excludes proven literal-boolean dead branches, but remains structural
// evidence only: unknown branches/functions may never execute.
func (a Analysis) HasCallStartingIn(start, end int) bool {
	if a.Error != "" {
		return false
	}
	i := sort.Search(len(a.Calls), func(i int) bool { return a.Calls[i].Start >= start })
	return i < len(a.Calls) && a.Calls[i].Start < end
}
