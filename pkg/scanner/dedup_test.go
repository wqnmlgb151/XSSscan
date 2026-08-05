package scanner

import (
	"testing"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
)

func TestClassifyAttackVector(t *testing.T) {
	tests := []struct {
		payload string
		want    attackVectorClass
	}{
		{`<script>alert(1)</script>`, VectorTagInjection},
		{`<img src=x onerror=alert(1)>`, VectorTagInjection},
		{`<svg onload=alert(1)>`, VectorTagInjection},
		{`<details open ontoggle=confirm()>`, VectorTagInjection},
		{`"><img src=x onerror=alert(1)>`, VectorAttrBreakout},
		{`'><svg onload=alert(1)>`, VectorAttrBreakout},
		{`';alert(1)//`, VectorJSBreakout},
		{`"-alert(1)-"`, VectorJSBreakout},
		{`{{constructor.constructor('alert(1)')()}}`, VectorTemplateInject},
		{`${alert(1)}`, VectorTemplateInject},
		{`javascript:alert(1)`, VectorURIInjection},
		{`data:text/html,<script>alert(1)</script>`, VectorURIInjection},
		{`vbscript:msgbox`, VectorURIInjection},
		{`expression(alert(1))`, VectorCSSInjection},
		{`-->`, VectorCommentBreakout},
		{`random text here`, VectorUnknown},
		{``, VectorUnknown},
	}

	for _, tt := range tests {
		got := classifyAttackVector(tt.payload)
		if got != tt.want {
			t.Errorf("classifyAttackVector(%q) = %q, want %q", tt.payload, got, tt.want)
		}
	}
}

func TestClassifyContext(t *testing.T) {
	tests := []struct {
		context ctx.ContextType
		want    contextClass
	}{
		{ctx.ContextHTMLBody, ContextHTMLExecute},
		{ctx.ContextHTMLTag, ContextHTMLExecute},
		{ctx.ContextHTMLAttrValue, ContextBreakout},
		{ctx.ContextJSString, ContextJSExecute},
		{ctx.ContextJSBlock, ContextJSExecute},
		{ctx.ContextJSTemplateLiteral, ContextJSExecute},
		{ctx.ContextURLAttr, ContextURL},
		{ctx.ContextCSSValue, ContextLimited},
		{ctx.ContextHTMLEntity, ContextLimited},
		{ctx.ContextUnknown, ContextLimited},
	}

	for _, tt := range tests {
		got := classifyContext(tt.context)
		if got != tt.want {
			t.Errorf("classifyContext(%v) = %q, want %q", tt.context, got, tt.want)
		}
	}
}

func TestPrimaryContextClass(t *testing.T) {
	tests := []struct {
		contexts []ctx.ContextType
		want     contextClass
	}{
		{[]ctx.ContextType{ctx.ContextHTMLBody}, ContextHTMLExecute},
		{[]ctx.ContextType{ctx.ContextHTMLAttrValue, ctx.ContextHTMLBody}, ContextHTMLExecute},
		{[]ctx.ContextType{ctx.ContextJSString}, ContextJSExecute},
		{[]ctx.ContextType{ctx.ContextCSSValue}, ContextLimited},
		{[]ctx.ContextType{ctx.ContextURLAttr}, ContextURL},
		{[]ctx.ContextType{ctx.ContextHTMLAttrValue}, ContextBreakout},
		{[]ctx.ContextType{}, ContextLimited},
	}

	for _, tt := range tests {
		got := primaryContextClass(tt.contexts)
		if got != tt.want {
			t.Errorf("primaryContextClass(%v) = %q, want %q", tt.contexts, got, tt.want)
		}
	}
}

func TestSemanticDedup_SameVectorSameContext(t *testing.T) {
	findings := []model.Finding{
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `<img src=x onerror=alert(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.7,
		},
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `<img src=x onerror=confirm(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.8,
		},
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `<img src=x onerror=prompt(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.6,
		},
	}

	result := SemanticDedup(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Confidence != 0.8 {
		t.Errorf("expected highest confidence 0.8, got %f", result[0].Confidence)
	}
}

func TestSemanticDedup_DifferentVectors(t *testing.T) {
	findings := []model.Finding{
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `<img src=x onerror=alert(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.7,
		},
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `<svg onload=alert(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.8,
		},
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `<script>alert(1)</script>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.9,
		},
	}

	// All three are tag_injection in html_execute — should collapse to 1
	result := SemanticDedup(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (all same vector class), got %d", len(result))
	}
	if result[0].Confidence != 0.9 {
		t.Errorf("expected highest confidence 0.9, got %f", result[0].Confidence)
	}
}

func TestSemanticDedup_DifferentParams(t *testing.T) {
	findings := []model.Finding{
		{
			URL:        "http://target.com/page?q=test&s=test",
			Parameter:  "q",
			Payload:    `<img src=x onerror=alert(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.7,
		},
		{
			URL:        "http://target.com/page?q=test&s=test",
			Parameter:  "s",
			Payload:    `<img src=x onerror=alert(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.8,
		},
	}

	result := SemanticDedup(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (different params), got %d", len(result))
	}
}

func TestSemanticDedup_DifferentContexts(t *testing.T) {
	findings := []model.Finding{
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `<img src=x onerror=alert(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.7,
		},
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `';alert(1)//`,
			Contexts:   []string{"js_string"},
			Confidence: 0.8,
		},
	}

	// Different context classes (html_execute vs js_execute) — both preserved
	result := SemanticDedup(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (different contexts), got %d", len(result))
	}
}

func TestSemanticDedup_PrefersVerified(t *testing.T) {
	findings := []model.Finding{
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `<img src=x onerror=alert(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.7,
		},
		{
			URL:                "http://target.com/page?q=test",
			Parameter:          "q",
			Payload:            `<svg onload=alert(1)>`,
			Contexts:           []string{"html_body"},
			Confidence:         0.7,
			ExecutionVerified:  true,
			ExecutionConfidence: 0.95,
		},
	}

	result := SemanticDedup(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if !result[0].ExecutionVerified {
		t.Error("expected the verified finding to be kept")
	}
}

func TestSemanticDedup_Empty(t *testing.T) {
	result := SemanticDedup([]model.Finding{})
	if len(result) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result))
	}
}

func TestSemanticDedup_Single(t *testing.T) {
	findings := []model.Finding{
		{
			URL:        "http://target.com/page?q=test",
			Parameter:  "q",
			Payload:    `<img src=x onerror=alert(1)>`,
			Contexts:   []string{"html_body"},
			Confidence: 0.7,
		},
	}
	result := SemanticDedup(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
}
