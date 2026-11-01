package verify

import (
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/payload"
)

func TestNestedResponseProbeDoesNotBorrowOuterEvidence(t *testing.T) {
	v := NewVerifier()
	p := payload.Payload{Value: `<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>`, Context: context.ContextHTMLBody}
	body := "<body>" + p.Value + "</body>"
	parent := memoizedResponseJSCall(body, p.Value)
	// The outer HTML has no inline JS call, but srcdoc's own script is executable.
	if confirmed, _ := parent(); confirmed {
		t.Fatal("outer document borrowed srcdoc call")
	}
	if _, ok := v.responseContext(body, p, parent); !ok {
		t.Fatal("nested document used parent-negative cache")
	}
	inert := payload.Payload{Value: `<iframe srcdoc="&lt;textarea&gt;alert(1)&lt;/textarea&gt;"></iframe>`, Context: context.ContextHTMLBody}
	if _, ok := v.responseContext("<body>"+inert.Value+"</body>", inert); ok {
		t.Fatal("nested inert text became executable")
	}
}

func BenchmarkResponseEvidenceRepeated(b *testing.B) {
	value := "alert(1)"
	body := strings.Repeat("<p>safe markup</p>", 6000) + "<script>" + value + "</script>"
	b.Run("separate", func(b *testing.B) {
		for b.Loop() {
			for range 3 {
				responseJSCall(body, value)
			}
		}
	})
	b.Run("local reuse", func(b *testing.B) {
		for b.Loop() {
			probe := memoizedResponseJSCall(body, value)
			for range 3 {
				probe()
			}
		}
	})
}
