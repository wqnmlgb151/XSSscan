package jsanalysis

import (
	"strings"

	"github.com/grafana/sobek/ast"
	"github.com/grafana/sobek/token"
)

// Source is a potential browser input, with byte offsets in the script text.
// Key is populated only for a literal get()/getItem() key.
type Source struct {
	Kind       string `json:"kind"`
	Key        string `json:"key,omitempty"`
	Start, End int
}

// Flow is a bounded static source-to-sink hypothesis, never execution proof.
type Flow struct {
	Source     Source
	Sink       string
	Start, End int
}

type flowValue struct {
	sources  []Source
	params   string
	function *flowFunction
}
type flowScope struct {
	values   map[string]flowValue
	parent   *flowScope
	function bool
}
type flowFunction struct {
	params *ast.ParameterList
	body   ast.ConciseBody
	scope  *flowScope
	origin *flowFunction
}
type flowAnalyzer struct {
	flows                              []Flow
	steps, depth, calls, shift, length int
	problem                            string
}

func analyzeFlows(program *ast.Program, shift, length int) ([]Flow, string) {
	a := flowAnalyzer{shift: shift, length: length}
	s := &flowScope{values: make(map[string]flowValue), function: true}
	statements := program.Body
	if shift > 0 && len(statements) == 1 {
		if wrapper, ok := statements[0].(*ast.FunctionDeclaration); ok {
			statements = wrapper.Function.Body.List
		}
	}
	a.list(statements, s)
	return a.flows, a.problem
}

func (s *flowScope) lookup(name string) (flowValue, bool) {
	for p := s; p != nil; p = p.parent {
		if v, ok := p.values[name]; ok {
			return v, true
		}
	}
	return flowValue{}, false
}
func (s *flowScope) assign(name string, v flowValue) {
	for p := s; p != nil; p = p.parent {
		if _, ok := p.values[name]; ok {
			p.values[name] = v
			return
		}
	}
	s.values[name] = v
}
func (a *flowAnalyzer) tick() bool {
	a.steps++
	if a.steps > 10000 || a.depth > 128 || a.calls > 8 {
		a.problem = "JavaScript data-flow work limit exceeded"
		return false
	}
	return a.problem == ""
}
func (a *flowAnalyzer) join(left, right flowValue) flowValue {
	out := flowValue{sources: append([]Source(nil), left.sources...)}
	out.function = left.function
	if out.function == nil {
		out.function = right.function
	}
	if left.function != nil && right.function != nil && left.function != right.function {
		a.problem = "JavaScript data-flow alternative function bodies require runtime analysis"
		out.function = nil
	}
	if left.params == right.params {
		out.params = left.params
	}
	for _, source := range right.sources {
		found := false
		for _, prior := range out.sources {
			found = found || prior == source
		}
		if !found {
			if len(out.sources) == 8 {
				a.problem = "JavaScript data-flow source limit exceeded"
				break
			}
			out.sources = append(out.sources, source)
		}
	}
	return out
}
func (a *flowAnalyzer) source(node ast.Node, kind, key string) flowValue {
	start, end := int(node.Idx0())-1-a.shift, int(node.Idx1())-1-a.shift
	if start < 0 || end > a.length || start >= end || len(key) > 128 {
		return flowValue{}
	}
	return flowValue{sources: []Source{{kind, strings.Clone(key), start, end}}}
}
func (a *flowAnalyzer) sink(node ast.Node, name string, value flowValue) {
	for _, source := range value.sources {
		f := Flow{source, strings.Clone(name), int(node.Idx0()) - 1 - a.shift, int(node.Idx1()) - 1 - a.shift}
		if f.Start < 0 || f.End > a.length {
			continue
		}
		found := false
		for _, prior := range a.flows {
			found = found || prior == f
		}
		if !found {
			if len(a.flows) == 64 {
				a.problem = "JavaScript data-flow result limit exceeded"
				return
			}
			a.flows = append(a.flows, f)
		}
	}
}
func member(expression ast.Expression) (ast.Expression, string) {
	switch n := expression.(type) {
	case *ast.DotExpression:
		return n.Left, n.Identifier.Name.String()
	case *ast.BracketExpression:
		if key, ok := n.Member.(*ast.StringLiteral); ok {
			return n.Left, key.Value.String()
		}
	}
	return nil, ""
}
func globalPath(expression ast.Expression, s *flowScope) string {
	return boundedGlobalPath(expression, s, 0)
}
func boundedGlobalPath(expression ast.Expression, s *flowScope, depth int) string {
	if depth > 16 {
		return ""
	}
	if id, ok := expression.(*ast.Identifier); ok {
		if _, shadowed := s.lookup(id.Name.String()); !shadowed {
			return id.Name.String()
		}
		return ""
	}
	left, name := member(expression)
	if left == nil {
		return ""
	}
	prefix := boundedGlobalPath(left, s, depth+1)
	if prefix == "" {
		return ""
	}
	return prefix + "." + name
}
func literalKey(expressions []ast.Expression) (string, bool) {
	if len(expressions) > 0 {
		if key, ok := expressions[0].(*ast.StringLiteral); ok {
			return key.Value.String(), true
		}
	}
	return "", false
}

func (a *flowAnalyzer) expression(expression ast.Expression, s *flowScope) flowValue {
	if expression == nil || !a.tick() {
		return flowValue{}
	}
	a.depth++
	defer func() { a.depth-- }()
	path := globalPath(expression, s)
	switch path {
	case "location.hash", "window.location.hash", "document.location.hash":
		return a.source(expression, "fragment", "")
	case "location.search", "window.location.search", "document.location.search":
		return a.source(expression, "query", "")
	case "window.name":
		return a.source(expression, "window.name", "")
	case "document.referrer":
		return a.source(expression, "referrer", "")
	}
	switch n := expression.(type) {
	case *ast.Identifier:
		v, _ := s.lookup(n.Name.String())
		return v
	case *ast.AssignExpression:
		value := a.expression(n.Right, s)
		if n.Operator != token.ASSIGN {
			value = a.join(a.expression(n.Left, s), value)
		}
		if id, ok := n.Left.(*ast.Identifier); ok {
			s.assign(id.Name.String(), value)
		} else {
			_, name := member(n.Left)
			switch name {
			case "innerHTML", "outerHTML", "srcdoc":
				a.sink(n.Left, name, value)
			}
		}
		return value
	case *ast.BinaryExpression:
		left := a.expression(n.Left, s)
		if b, ok := n.Left.(*ast.BooleanLiteral); ok && ((n.Operator == token.LOGICAL_AND && !b.Value) || (n.Operator == token.LOGICAL_OR && b.Value)) {
			return left
		}
		if n.Operator == token.LOGICAL_AND || n.Operator == token.LOGICAL_OR || n.Operator == token.COALESCE {
			if _, ok := n.Left.(*ast.BooleanLiteral); ok {
				if n.Operator == token.COALESCE {
					return left
				}
				return a.join(left, a.expression(n.Right, s))
			}
			branch := a.cloneFlowScope(s)
			right := a.expression(n.Right, branch)
			a.mergeScopes(s, s, branch)
			return a.join(left, right)
		}
		return a.join(left, a.expression(n.Right, s))
	case *ast.TemplateLiteral:
		var value flowValue
		for _, part := range n.Expressions {
			value = a.join(value, a.expression(part, s))
		}
		return value
	case *ast.SequenceExpression:
		var value flowValue
		for _, part := range n.Sequence {
			value = a.expression(part, s)
		}
		return value
	case *ast.ConditionalExpression:
		a.expression(n.Test, s)
		if b, ok := n.Test.(*ast.BooleanLiteral); ok {
			if b.Value {
				return a.expression(n.Consequent, s)
			}
			return a.expression(n.Alternate, s)
		}
		left, right := a.cloneFlowScope(s), a.cloneFlowScope(s)
		value := a.join(a.expression(n.Consequent, left), a.expression(n.Alternate, right))
		a.mergeScopes(s, left, right)
		return value
	case *ast.NewExpression:
		if name := globalPath(n.Callee, s); name == "URLSearchParams" || name == "window.URLSearchParams" {
			if len(n.ArgumentList) > 0 {
				v := a.expression(n.ArgumentList[0], s)
				if len(v.sources) == 1 {
					return flowValue{params: v.sources[0].Kind}
				}
			}
		}
	case *ast.CallExpression:
		return a.call(n, s)
	case *ast.FunctionLiteral:
		return flowValue{function: &flowFunction{params: n.ParameterList, body: n.Body, scope: s}}
	case *ast.ArrowFunctionLiteral:
		return flowValue{function: &flowFunction{params: n.ParameterList, body: n.Body, scope: s}}
	case *ast.AwaitExpression:
		return a.expression(n.Argument, s)
	case *ast.UnaryExpression:
		return a.expression(n.Operand, s)
	}
	return flowValue{}
}

func (a *flowAnalyzer) call(n *ast.CallExpression, s *flowScope) flowValue {
	callee := a.expression(n.Callee, s)
	args := make([]flowValue, len(n.ArgumentList))
	var combined flowValue
	for i, arg := range n.ArgumentList {
		args[i] = a.expression(arg, s)
		combined = a.join(combined, args[i])
	}
	if callee.function != nil {
		return a.invoke(callee.function, args)
	}
	left, name := member(n.Callee)
	if left != nil {
		receiver := a.expression(left, s)
		if key, ok := literalKey(n.ArgumentList); ok {
			if name == "get" && (receiver.params == "query" || receiver.params == "fragment") {
				return a.source(n, receiver.params, key)
			}
			storage := globalPath(left, s)
			storage = strings.TrimPrefix(storage, "window.")
			if name == "getItem" && (storage == "localStorage" || storage == "sessionStorage") {
				return a.source(n, storage, key)
			}
		}
		if name == "insertAdjacentHTML" && len(args) > 1 {
			a.sink(n, name, args[1])
		}
		if name == "setAttribute" && len(args) > 1 {
			if key, ok := literalKey(n.ArgumentList); ok && (strings.HasPrefix(strings.ToLower(key), "on") || strings.EqualFold(key, "srcdoc")) {
				a.sink(n, "setAttribute("+strings.ToLower(key)+")", args[1])
			}
		}
		// String transforms retain the input for planning; no sanitizer is
		// assumed safe and no static hypothesis is promoted to a finding.
		combined = a.join(combined, receiver)
	}
	path := globalPath(n.Callee, s)
	switch path {
	case "eval", "window.eval", "Function", "window.Function", "document.write", "document.writeln":
		a.sink(n, path, combined)
	case "setTimeout", "setInterval", "window.setTimeout", "window.setInterval":
		if len(args) > 0 {
			a.sink(n, path, args[0])
		}
	}
	for _, value := range args {
		if value.function != nil {
			a.invoke(value.function, nil)
		}
	}
	return combined
}

func (a *flowAnalyzer) invoke(f *flowFunction, args []flowValue) flowValue {
	a.calls++
	defer func() { a.calls-- }()
	if !a.tick() {
		return flowValue{}
	}
	s := &flowScope{values: make(map[string]flowValue), parent: f.scope, function: true}
	if f.params != nil {
		for i, p := range f.params.List {
			if id, ok := p.Target.(*ast.Identifier); ok {
				var v flowValue
				if i < len(args) {
					v = args[i]
				}
				s.values[id.Name.String()] = v
			}
		}
	}
	switch body := f.body.(type) {
	case *ast.BlockStatement:
		return a.list(body.List, s)
	case *ast.ExpressionBody:
		return a.expression(body.Expression, s)
	}
	return flowValue{}
}

func (a *flowAnalyzer) bindings(bindings []*ast.Binding, s, decl *flowScope) {
	for _, b := range bindings {
		if !a.tick() {
			return
		}
		if id, ok := b.Target.(*ast.Identifier); ok {
			decl.values[id.Name.String()] = a.expression(b.Initializer, s)
		}
	}
}
func (a *flowAnalyzer) list(statements []ast.Statement, s *flowScope) flowValue {
	// Function declarations are available before their source position.
	for _, stmt := range statements {
		if !a.tick() {
			return flowValue{}
		}
		if export, ok := stmt.(*ast.ExportDeclaration); ok && export.HoistableDeclaration != nil && export.HoistableDeclaration.FunctionDeclaration != nil {
			stmt = export.HoistableDeclaration.FunctionDeclaration
		}
		if n, ok := stmt.(*ast.FunctionDeclaration); ok && n.Function.Name != nil {
			s.values[n.Function.Name.Name.String()] = flowValue{function: &flowFunction{params: n.Function.ParameterList, body: n.Function.Body, scope: s}}
		}
	}
	var value flowValue
	for _, stmt := range statements {
		value = a.join(value, a.statement(stmt, s))
		if a.problem != "" {
			break
		}
	}
	return value
}
func (a *flowAnalyzer) statement(stmt ast.Statement, s *flowScope) flowValue {
	if stmt == nil || !a.tick() {
		return flowValue{}
	}
	switch n := stmt.(type) {
	case *ast.ExpressionStatement:
		a.expression(n.Expression, s)
	case *ast.ExportDeclaration:
		if n.Variable != nil {
			return a.statement(n.Variable, s)
		}
		if n.LexicalDeclaration != nil {
			return a.statement(n.LexicalDeclaration, s)
		}
		a.expression(n.AssignExpression, s)
	case *ast.VariableStatement:
		decl := s
		for !decl.function && decl.parent != nil {
			decl = decl.parent
		}
		a.bindings(n.List, s, decl)
	case *ast.LexicalDeclaration:
		a.bindings(n.List, s, s)
	case *ast.ReturnStatement:
		return a.expression(n.Argument, s)
	case *ast.BlockStatement:
		return a.list(n.List, &flowScope{values: make(map[string]flowValue), parent: s})
	case *ast.IfStatement:
		a.expression(n.Test, s)
		if b, ok := n.Test.(*ast.BooleanLiteral); ok {
			if b.Value {
				return a.statement(n.Consequent, s)
			}
			return a.statement(n.Alternate, s)
		}
		left, right := a.cloneFlowScope(s), a.cloneFlowScope(s)
		value := a.join(a.statement(n.Consequent, left), a.statement(n.Alternate, right))
		a.mergeScopes(s, left, right)
		return value
	case *ast.WhileStatement:
		a.expression(n.Test, s)
		if b, ok := n.Test.(*ast.BooleanLiteral); ok && !b.Value {
			return flowValue{}
		}
		branch := a.cloneFlowScope(s)
		value := a.statement(n.Body, branch)
		a.mergeScopes(s, s, branch)
		return value
	}
	return flowValue{}
}
func (a *flowAnalyzer) cloneFlowScope(s *flowScope) *flowScope {
	return a.copyFlowScope(s, make(map[*flowScope]*flowScope), make(map[*flowFunction]*flowFunction))
}
func (a *flowAnalyzer) copyFlowScope(s *flowScope, scopes map[*flowScope]*flowScope, functions map[*flowFunction]*flowFunction) *flowScope {
	if s == nil {
		return nil
	}
	if prior := scopes[s]; prior != nil {
		return prior
	}
	out := &flowScope{values: make(map[string]flowValue, len(s.values)), function: s.function}
	scopes[s] = out
	out.parent = a.copyFlowScope(s.parent, scopes, functions)
	for name, value := range s.values {
		if !a.tick() {
			break
		}
		if f := value.function; f != nil {
			clone := functions[f]
			if clone == nil {
				origin := f.origin
				if origin == nil {
					origin = f
				}
				clone = &flowFunction{params: f.params, body: f.body, origin: origin}
				functions[f] = clone
				clone.scope = a.copyFlowScope(f.scope, scopes, functions)
			}
			value.function = clone
		}
		out.values[name] = value
	}
	return out
}
func (a *flowAnalyzer) mergeScopes(out, left, right *flowScope) {
	if out == nil {
		return
	}
	for name, value := range left.values {
		if !a.tick() {
			return
		}
		rightValue := right.values[name]
		var preserved *flowFunction
		if f := out.values[name].function; f != nil && value.function != nil && rightValue.function != nil {
			identity := func(fn *flowFunction) *flowFunction {
				if fn.origin != nil {
					return fn.origin
				}
				return fn
			}
			if identity(f) == identity(value.function) && identity(f) == identity(rightValue.function) {
				preserved = f
				value.function, rightValue.function = nil, nil
			}
		}
		merged := a.join(value, rightValue)
		if preserved != nil {
			merged.function = preserved
		}
		out.values[name] = merged
	}
	for name, value := range right.values {
		if !a.tick() {
			return
		}
		if _, ok := left.values[name]; !ok {
			out.values[name] = value
		}
	}
	a.mergeScopes(out.parent, left.parent, right.parent)
}
