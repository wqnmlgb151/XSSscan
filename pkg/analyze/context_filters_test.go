package analyze

import (
	ctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"strings"
	"testing"
)

func TestContextFiltersBoundariesAndOccurrenceIsolation(t *testing.T) {
	start, end := "xsscanstartmarker", "xsscanendmarker"
	body := `<div title="` + start + `&lt;&gt;&quot;&#39;()=` + end + `">` + start + `<>"'()=` + end + `</div>`
	got := DetectContextFilters(body, start, end)
	if got[ctx.ContextHTMLAttrValue] == nil || got[ctx.ContextHTMLAttrValue].AllowsDoubleQuote() || got[ctx.ContextHTMLAttrValue].AllowsAngleBrackets() {
		t.Fatalf("attribute filter contaminated: %+v", got)
	}
	if got[ctx.ContextHTMLBody] == nil || !got[ctx.ContextHTMLBody].AllowsDoubleQuote() || !got[ctx.ContextHTMLBody].AllowsAngleBrackets() {
		t.Fatalf("body filter contaminated: %+v", got)
	}
	if got := DetectContextFilters(`<div title="`+start+`&quot;`+end+`">`, start, end); got[ctx.ContextHTMLAttrValue] == nil || got[ctx.ContextHTMLAttrValue].AllowsDoubleQuote() {
		t.Fatal("surrounding tag quote contaminated probe")
	}
	if got := DetectContextFilters(`<p>`+start+`&lt;`, start, end); len(got) != 0 {
		t.Fatal("truncated probe justified pruning")
	}
	if got := DetectContextFilters(`<p>`+start+`&lt;`+end+`</p><p>`+start+`<>`+end+`</p>`, start, end); got[ctx.ContextHTMLBody] == nil || !got[ctx.ContextHTMLBody].AllowsAngleBrackets() {
		t.Fatal("permissive same-context occurrence lost")
	}
}

func TestFilterReflectionAmplificationIsBounded(t *testing.T) {
	for _, count := range []int{17, 10000} {
		body := strings.Repeat("<p>xsscanstart<>xsscanend</p>", count)
		if got := DetectContextFilters(body, "xsscanstart", "xsscanend"); len(got) != 0 {
			t.Fatalf("large reflected probe was parsed/pruned: count=%d", count)
		}
	}
}

func BenchmarkFilterReflectionLimit(b *testing.B) {
	body := strings.Repeat("<p>xsscanstart<>xsscanend</p>", 10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectContextFilters(body, "xsscanstart", "xsscanend")
	}
}
