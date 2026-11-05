package payload

import (
	"strings"
	"testing"

	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func TestMinimalPresetChoosesCompatibleQuote(t *testing.T) {
	for _, kind := range []xctx.ContextType{xctx.ContextJSString, xctx.ContextHTMLAttrValue} {
		for _, quote := range []string{"'", `"`} {
			g := NewGenerator()
			g.SetPreset(PresetMinimal)
			got := g.Generate(model.InjectionPoint{Contexts: []xctx.Context{{Type: kind, QuoteChar: quote}}})
			if len(got) != 1 || !strings.HasPrefix(got[0].Value, quote) {
				t.Errorf("kind=%s quote=%s got=%+v", kind, quote, got)
			}
		}
	}
}

func TestQuotedAttributeCompatibility(t *testing.T) {
	for _, quote := range []string{"'", `"`} {
		got := NewGenerator().Generate(model.InjectionPoint{Contexts: []xctx.Context{{Type: xctx.ContextHTMLAttrValue, QuoteChar: quote}}})
		for _, p := range got {
			if (strings.HasPrefix(p.Value, "'") && quote != "'" || strings.HasPrefix(p.Value, `"`) && quote != `"`) && !strings.Contains(p.Value, quote) {
				t.Fatalf("wrong quoted attribute candidate: quote=%s payload=%s", quote, p.Value)
			}
		}
	}
}

func TestMixedQuoteAttributePayloadRetained(t *testing.T) {
	for _, tc := range []struct{ quote, value string }{
		{`"`, `'" autofocus onfocus=alert(1) x="`},
		{"'", `"' autofocus onfocus=alert(1) x='`},
	} {
		g := NewGenerator()
		g.SetCustomPayloads([]Payload{{Value: tc.value, Type: PayloadTypeCustom}})
		got := g.Generate(model.InjectionPoint{Contexts: []xctx.Context{{Type: xctx.ContextHTMLAttrValue, QuoteChar: tc.quote}}})
		found := false
		for _, p := range got {
			found = found || p.Value == tc.value
		}
		if !found {
			t.Fatalf("mixed quote removed: %+v", tc)
		}
	}
}

func TestDetectorToMinimalGenerator(t *testing.T) {
	for _, tc := range []struct{ body, quote string }{
		{`<input value='MARKER'>`, "'"}, {`<input value="MARKER">`, `"`},
		{`<script>window.q="MARKER";</script>`, `"`},
	} {
		contexts, _ := xctx.NewDetector().Detect(xctx.Reflection{Content: tc.body, ParamValue: "MARKER"})
		g := NewGenerator()
		g.SetPreset(PresetMinimal)
		got := g.Generate(model.InjectionPoint{Contexts: contexts})
		if len(got) != 1 || !strings.HasPrefix(got[0].Value, tc.quote) {
			t.Fatalf("body=%s contexts=%+v payloads=%+v", tc.body, contexts, got)
		}
	}
}
