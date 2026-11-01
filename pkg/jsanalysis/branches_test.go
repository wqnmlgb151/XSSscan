package jsanalysis

import (
	"strings"
	"testing"
)

func TestConstantBranchCallEvidence(t *testing.T) {
	for _, tc := range []struct {
		source string
		call   bool
	}{
		{`if(false){alert(1)}`, false}, {`if(true){}else{alert(1)}`, false},
		{`while(false){alert(1)}`, false}, {`false && alert(1)`, false},
		{`true || alert(1)`, false}, {`true ? 0 : alert(1)`, false},
		{`false ? alert(1) : 0`, false}, {`if(false){if(true){alert(1)}}`, false},
		{`if(false){var x=alert(1)}`, false}, {`while(false){var x=alert(1)}`, false},
		{`function f(){if(false){var x=alert(1)}}`, false},
		{`if(true){var x=alert(1)}`, true},
		{`if(true){alert(1)}`, true}, {`if(false){}else{alert(1)}`, true},
		{`true && alert(1)`, true}, {`false || alert(1)`, true},
		{`do{alert(1)}while(false)`, true}, {`if(flag){alert(1)}`, true},
		{`Boolean(false) && alert(1)`, true}, {`false ?? alert(1)`, true},
		// Function bodies are deliberately conservative (hoisting/callers).
		{`if(false){function f(){alert(1)}}`, true},
		{`false && (()=>alert(1))`, true},
	} {
		for _, mode := range []SourceMode{ScriptMode, HandlerMode, ModuleMode} {
			a := ParseWithMode(tc.source, mode)
			start := strings.Index(tc.source, "alert(1)")
			if a.Error != "" || a.HasCallStartingIn(start, start+8) != tc.call {
				t.Errorf("mode=%v source=%s want=%v got=%+v", mode, tc.source, tc.call, a)
			}
		}
	}
}

func TestConstantBranchConstructorAndTag(t *testing.T) {
	for _, tc := range []struct {
		source, needle string
		call           bool
	}{
		{`if(false){new Alert(1)}`, "new Alert", false},
		{`if(true){new Alert(1)}`, "new Alert", true},
		{"false && alert`1`", "alert", false},
		{"true && alert`1`", "alert", true},
	} {
		a := Parse(tc.source, false)
		i := strings.Index(tc.source, tc.needle)
		if i < 0 || a.Error != "" || a.HasCallStartingIn(i, i+len(tc.needle)) != tc.call {
			t.Fatalf("%s %+v", tc.source, a)
		}
	}
}

func TestDeadBranchStillClassifiesAndValidates(t *testing.T) {
	source := "if(false){const q='MARKER';const r=/MARKER/;const t=`MARKER`;/* MARKER */}"
	a := Parse(source, false)
	for _, part := range []struct {
		text string
		kind Kind
	}{{"'MARKER'", String}, {"/MARKER/", Regexp}, {"`MARKER`", Template}, {"/* MARKER", Comment}} {
		if got := a.At(strings.Index(source, part.text) + 2); got.Kind != part.kind || a.Error != "" {
			t.Fatalf("lost dead-branch literal: %s %+v error=%s", part.text, got, a.Error)
		}
	}
	if a := Parse(`if(false){let x=;alert(1)}`, false); a.Error == "" {
		t.Fatal("dead syntax was not validated")
	}
}
