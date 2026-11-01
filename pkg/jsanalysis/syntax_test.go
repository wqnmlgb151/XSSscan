package jsanalysis

import (
	"strings"
	"testing"
)

func TestEarlyErrorsCannotSupplyCallEvidence(t *testing.T) {
	for _, source := range []string{
		`with({}){alert(1)}`,
		`const n=010; alert(1);`,
		`const s='\1'; alert(1);`,
		`function f(a,a){alert(1)}`,
		`delete x; alert(1);`,
		`let eval=1; alert(1);`,
		`arguments=1; alert(1);`,
		`const x=1; const x=2; alert(1);`,
		`import {x} from 'm'; const x=2; alert(1);`,
		`export const x=1; export {x as x}; alert(1);`,
		`export {missing}; alert(1);`,
		`let implements=1; alert(1);`,
		`function f(a=1){'use strict';alert(1)}`,
		`class C{#x;#x;} alert(1);`,
	} {
		a := ParseWithMode(source, ModuleMode)
		if a.Error == "" || a.At(0).Kind != Unknown || a.HasCallStartingIn(0, len(source)) {
			t.Errorf("invalid module provided evidence: %s %+v", source, a)
		}
	}
	for _, mode := range []SourceMode{ScriptMode, HandlerMode} {
		a := ParseWithMode(`"use strict"; with({}){alert(1)}`, mode)
		if a.Error == "" {
			t.Errorf("strict early error missed mode=%d", mode)
		}
	}
	if a := ParseWithMode(`with({}){alert(1)}`, ScriptMode); a.Error != "" {
		t.Fatalf("sloppy script rejected: %+v", a)
	}
}

func TestHTMLCommentsAndHashbangOffsets(t *testing.T) {
	for _, source := range []string{"<!-- '\nMARKER()", "--> '\nMARKER()", "#! ignored '\nMARKER()", "void 0;\u2028  --> '\nMARKER()", "void 0;\u2029\t--> '\nMARKER()"} {
		a := Parse(source, false)
		i := strings.Index(source, "MARKER")
		if a.Error != "" || a.At(i).Kind != Code || !a.HasCallStartingIn(i, i+6) {
			t.Fatalf("line comment corrupted code: %q %+v", source, a)
		}
	}
}
