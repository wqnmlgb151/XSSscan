package scanner

import (
	"reflect"
	"testing"

	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
)

func TestPayloadBudgetPreservesContextsAndQuotes(t *testing.T) {
	input := []payload.Payload{
		{Value: "body1", Context: xctx.ContextHTMLBody}, {Value: "body2", Context: xctx.ContextHTMLBody}, {Value: "body3", Context: xctx.ContextHTMLBody},
		{Value: `" onfocus=alert(1)`, Context: xctx.ContextHTMLAttrValue}, {Value: `" onmouseover=alert(1)`, Context: xctx.ContextHTMLAttrValue},
		{Value: `' onfocus=alert(1)`, Context: xctx.ContextHTMLAttrValue},
		{Value: `';alert(1)//`, Context: xctx.ContextJSString}, {Value: `"-alert(1)-"`, Context: xctx.ContextJSString},
	}
	want := []payload.Payload{input[0], input[3], input[5], input[6], input[7], input[1]}
	before := append([]payload.Payload(nil), input...)
	if got := limitPayloads(input, 6); !reflect.DeepEqual(got, want) {
		t.Fatalf("budget=%+v want=%+v", got, want)
	}
	if !reflect.DeepEqual(input, before) {
		t.Fatal("selection mutated input")
	}
	for _, limit := range []int{0, -1, len(input), len(input) + 1} {
		if got := limitPayloads(input, limit); !reflect.DeepEqual(got, input) {
			t.Fatalf("unlimited/nonbinding=%d got=%+v", limit, got)
		}
	}
	if got := limitPayloads(input, 1); !reflect.DeepEqual(got, input[:1]) {
		t.Fatalf("tiny budget=%+v", got)
	}
	if got := limitPayloads(nil, 3); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestPayloadBudgetPreservesSingleGroupOrder(t *testing.T) {
	input := []payload.Payload{{Value: "one", Context: xctx.ContextHTMLBody}, {Value: "two", Context: xctx.ContextHTMLBody}, {Value: "three", Context: xctx.ContextHTMLBody}}
	if got := limitPayloads(input, 2); !reflect.DeepEqual(got, input[:2]) {
		t.Fatal(got)
	}
}
