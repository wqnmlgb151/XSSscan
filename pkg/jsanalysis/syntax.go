package jsanalysis

import (
	"fmt"

	"github.com/evanw/esbuild/pkg/api"
)

// validateSyntax checks early errors omitted by the AST parser. Transform only
// accepts an in-memory string: it does not resolve imports, load files or execute
// JavaScript. Its output is discarded; source spans always come from Sobek.
func validateSyntax(source string, mode SourceMode) string {
	if mode == ModuleMode {
		// Modules are strict even when they contain no import/export statements.
		// The synthetic empty export affects validation only, never evidence spans.
		source += "\nexport {};"
	}
	r := api.Transform(source, api.TransformOptions{
		Loader:        api.LoaderJS,
		Target:        api.ESNext,
		LogLevel:      api.LogLevelSilent,
		LegalComments: api.LegalCommentsNone,
	})
	if len(r.Errors) == 0 {
		return ""
	}
	m := r.Errors[0]
	if m.Location != nil {
		line := m.Location.Line
		if mode == HandlerMode {
			line--
		}
		return fmt.Sprintf("JavaScript early error at line %d column %d: %s", max(1, line), m.Location.Column+1, m.Text)
	}
	return "JavaScript early error: " + m.Text
}
