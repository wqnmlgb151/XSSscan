package jsanalysis

import (
	"strings"
	"testing"
)

func BenchmarkRepeatedScript(b *testing.B) {
	source := strings.Repeat("void 'literal';\n", 800) + "alert(1)"
	b.ReportAllocs()
	for b.Loop() {
		a := Parse(source, false)
		if a.Error != "" {
			b.Fatal(a.Error)
		}
	}
}

func BenchmarkUncachedScript(b *testing.B) {
	source := strings.Repeat("void 'literal';\n", 800) + "alert(1)"
	b.ReportAllocs()
	for b.Loop() {
		if a := parseUncached(source, ScriptMode); a.Error != "" {
			b.Fatal(a.Error)
		}
	}
}

func BenchmarkIndexedCallLookup(b *testing.B) {
	source := strings.Repeat("f();\n", 800)
	a := Parse(source, false)
	if a.Error != "" {
		b.Fatal(a.Error)
	}
	b.ReportAllocs()
	index := 0
	for b.Loop() {
		start := (index % 800) * 5
		index++
		if !a.HasCallStartingIn(start, start+4) {
			b.Fatal("call lost")
		}
	}
}
