package jsanalysis

import (
	"strings"
	"testing"
)

func TestModuleSpansAndCalls(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		kind         Kind
		call         bool
	}{
		{"import_default", `import x from 'MARKER';`, String, false},
		{"import_side_effect", `import "MARKER//path";`, String, false},
		{"re_export", `export {x} from 'MARKER/*path';`, String, false},
		{"export_star", `export * from "MARKER";`, String, false},
		{"import_named_string", `import {"MARKER" as x} from 'm';`, String, false},
		{"export_string", `export const x='汉MARKER';`, String, false},
		{"comment", `import x from 'm'; /* MARKER() */`, Comment, false},
		{"regexp", `export const r=/MARKER()/;`, Regexp, false},
		{"template", "export const x=`MARKER()`;", Template, false},
		{"top_level_await", `await MARKER();`, Code, true},
		{"export_call", `export default MARKER();`, Code, true},
		{"import_meta", `import.meta.url; MARKER();`, Code, true},
		{"dynamic_import_argument", `import(MARKER());`, Code, true},
		{"lazy_function", `export function f(){ MARKER(); }`, Code, true},
		{"hashbang", "#! ignored '\nMARKER();", Code, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ParseWithMode(tc.source, ModuleMode)
			i := strings.Index(tc.source, "MARKER")
			if a.Error != "" || a.At(i).Kind != tc.kind || a.HasCallStartingIn(i, i+6) != tc.call {
				t.Fatalf("kind=%s call=%t: %+v at=%+v", tc.kind, tc.call, a, a.At(i))
			}
		})
	}
}

func TestSourceModesStayDistinct(t *testing.T) {
	if a := ParseWithMode(`import x from 'm'; alert(1);`, ScriptMode); a.Error == "" {
		t.Fatal("module syntax accepted as classic script")
	}
	if a := ParseWithMode(`return alert(1)`, HandlerMode); a.Error != "" || !a.HasCallStartingIn(7, 15) {
		t.Fatalf("handler return rejected: %+v", a)
	}
	for _, tc := range []struct {
		source string
		mode   SourceMode
	}{
		{`return alert(1)`, ModuleMode},
		{`import x from 'm';`, HandlerMode},
		{`export const x=; alert(1)`, ModuleMode},
		{`alert(1)`, SourceMode(255)},
	} {
		a := ParseWithMode(tc.source, tc.mode)
		if a.Error == "" || a.At(0).Kind != Unknown || a.HasCallStartingIn(0, len(tc.source)) {
			t.Fatalf("invalid source treated as evidence: %+v", a)
		}
	}
}
