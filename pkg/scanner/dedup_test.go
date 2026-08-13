package scanner

import (
	"testing"

	"github.com/xsscan/xsscan/pkg/internal/urlutil"

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

	// All are tag_injection + html_execute, but exploit classes differ:
	// event (onerror/onload) vs script (<script>) — keep both groups, 2 findings
	result := SemanticDedup(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (event vs script exploit class), got %d", len(result))
	}
	found := false
	for _, r := range result {
		if r.Confidence == 0.9 && r.Payload == `<script>alert(1)</script>` {
			found = true
		}
	}
	if !found {
		t.Error("expected <script> finding to survive dedup")
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
			URL:                 "http://target.com/page?q=test",
			Parameter:           "q",
			Payload:             `<svg onload=alert(1)>`,
			Contexts:            []string{"html_body"},
			Confidence:          0.7,
			ExecutionVerified:   true,
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

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"http://target.com/page?q=test", "http://target.com/page"},
		{"http://target.com/page?q=test#frag", "http://target.com/page"},
		{"http://target.com/page#frag", "http://target.com/page"},
		{"http://target.com/page", "http://target.com/page"},
		{"http://target.com/page?", "http://target.com/page"},
		{"://invalid", "://invalid"}, // parse failure → returned as-is
	}
	for _, tt := range tests {
		if got := urlutil.NormalizeForDedup(tt.in); got != tt.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestClassifyExploit(t *testing.T) {
	tests := []struct {
		payload string
		want    exploitClass
	}{
		{`<script>alert(1)</script>`, ExploitScriptTag},
		{`</script><script>alert(1)</script>`, ExploitBreakout},
		{`</textarea><svg onload=alert(1)>`, ExploitBreakout},
		{`<img src=x onerror=alert(1)>`, ExploitEventHandle},
		{`" onmouseover="alert(1)" x="`, ExploitEventHandle},
		{`javascript:alert(1)`, ExploitProtocol},
		{`data:text/html,<script>alert(1)</script>`, ExploitScriptTag},
		{`<iframe srcdoc="<script>alert(1)</script>">`, ExploitNestedExec},
		{`<meta http-equiv=refresh content="0;url=javascript:alert(1)">`, ExploitProtocol},
		{`<link rel=import href="data:text/html,<script>alert(1)</script>">`, ExploitScriptTag},
		{`<base href="//evil.com/">`, ExploitImport},
		{`{{constructor.constructor('alert(1)')()}}`, ExploitOther},
		{`${alert(1)}`, ExploitOther},
		{`random text`, ExploitOther},
	}
	for _, tt := range tests {
		if got := classifyExploit(tt.payload); got != tt.want {
			t.Errorf("classifyExploit(%q) = %q, want %q", tt.payload, got, tt.want)
		}
	}
}

func TestSemanticDedup_NormalizesURL(t *testing.T) {
	// Same base URL with different query strings must collapse to one key
	findings := []model.Finding{
		{URL: "http://target.com/page?q=<script>alert(1)</script>", Parameter: "q", Payload: `<script>alert(1)</script>`, Contexts: []string{"html_body"}, Confidence: 0.7},
		{URL: "http://target.com/page?q=<script>alert(2)</script>", Parameter: "q", Payload: `<script>alert(1)</script>`, Contexts: []string{"html_body"}, Confidence: 0.8},
	}
	result := SemanticDedup(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding after URL normalization, got %d", len(result))
	}
	if result[0].Confidence != 0.8 {
		t.Errorf("expected highest confidence 0.8, got %f", result[0].Confidence)
	}
}

func TestSemanticDedup_DeterministicOrder(t *testing.T) {
	findings := []model.Finding{
		{URL: "http://a.com/p?q=1", Parameter: "q", Payload: `<script>alert(1)</script>`, Contexts: []string{"html_body"}, Confidence: 0.7},
		{URL: "http://a.com/p?q=2", Parameter: "q", Payload: `<img src=x onerror=alert(1)>`, Contexts: []string{"html_body"}, Confidence: 0.8},
		{URL: "http://a.com/p?q=3", Parameter: "q", Payload: `javascript:alert(1)`, Contexts: []string{"html_body"}, Confidence: 0.9},
		{URL: "http://a.com/p?q=4", Parameter: "q", Payload: `<img src=x onerror=confirm(1)>`, Contexts: []string{"html_body"}, Confidence: 0.6},
	}

	// Determinism: the SAME input must produce the SAME output across runs
	// (no map-iteration randomness). Output follows first-seen order of the
	// given input, so different input orderings legitimately differ.
	for _, input := range [][]model.Finding{
		findings,
		{findings[2], findings[0], findings[3], findings[1]},
	} {
		first := SemanticDedup(input)
		for run := 0; run < 3; run++ {
			got := SemanticDedup(input)
			if len(got) != len(first) {
				t.Fatalf("run %d: got %d findings, want %d", run, len(got), len(first))
			}
			for i := range first {
				if got[i].Payload != first[i].Payload {
					t.Errorf("run %d: position %d payload = %q, want %q (non-deterministic output order)",
						run, i, got[i].Payload, first[i].Payload)
				}
			}
		}
	}
}

// TestAggregateFindings_CollapsesSameParamContext verifies that findings
// sharing URL+param+context class+type collapse into one entry with all
// payload variants attached.
func TestAggregateFindings_CollapsesSameParamContext(t *testing.T) {
	findings := []model.Finding{
		{URL: "http://a.com/p?q=1", Parameter: "q", Type: model.ReflectedXSS, Payload: `<script>alert(1)</script>`, Contexts: []string{"html_body"}, Confidence: 0.8, Severity: model.High},
		{URL: "http://a.com/p?q=2", Parameter: "q", Type: model.ReflectedXSS, Payload: `<img src=x onerror=alert(1)>`, Contexts: []string{"html_body"}, Confidence: 0.85, Severity: model.High},
		{URL: "http://a.com/p?q=3", Parameter: "q", Type: model.ReflectedXSS, Payload: `javascript:alert(1)`, Contexts: []string{"html_body"}, Confidence: 0.9, Severity: model.Critical},
		{URL: "http://a.com/p?q=4", Parameter: "q", Type: model.ReflectedXSS, Payload: `';alert(1)//`, Contexts: []string{"js_string"}, Confidence: 0.7, Severity: model.High},
		{URL: "http://a.com/p?s=1", Parameter: "s", Type: model.ReflectedXSS, Payload: `<svg onload=alert(1)>`, Contexts: []string{"html_body"}, Confidence: 0.6, Severity: model.Medium},
		{URL: "http://a.com/p?q=5", Parameter: "q", Type: model.StoredXSS, Payload: `MARKER`, Contexts: []string{"stored"}, Confidence: 0.85, Severity: model.High},
	}

	result := AggregateFindings(findings)
	// Groups: q/html_body/reflected (3), q/js_string (1), s/html_body (1), q/stored (1) = 4
	if len(result) != 4 {
		t.Fatalf("expected 4 aggregated findings, got %d", len(result))
	}

	for _, f := range result {
		switch {
		case f.Parameter == "q" && f.Type == model.ReflectedXSS && f.Contexts[0] == "html_body":
			if len(f.Payloads) != 3 {
				t.Errorf("expected 3 payload variants, got %d: %v", len(f.Payloads), f.Payloads)
			}
			// Primary = highest confidence; severity promotes to group max
			if f.Confidence != 0.9 || f.Severity != model.Critical {
				t.Errorf("expected primary confidence 0.9 + severity critical, got %f/%s", f.Confidence, f.Severity)
			}
		case f.Parameter == "q" && f.Contexts[0] == "js_string":
			if len(f.Payloads) != 1 {
				t.Errorf("js_string group should have 1 variant, got %v", f.Payloads)
			}
		case f.Parameter == "s":
			if len(f.Payloads) != 1 {
				t.Errorf("param s should have 1 variant, got %v", f.Payloads)
			}
		case f.Type == model.StoredXSS:
			if len(f.Payloads) != 1 {
				t.Errorf("stored finding should not be merged with reflected, got %v", f.Payloads)
			}
		default:
			t.Errorf("unexpected aggregated finding: %+v", f)
		}
	}
}

// TestAggregateFindings_VerifiedPromotes verifies a verified variant in the
// group marks the aggregated finding as execution-verified.
func TestAggregateFindings_VerifiedPromotes(t *testing.T) {
	findings := []model.Finding{
		{URL: "http://a.com/p?q=1", Parameter: "q", Type: model.ReflectedXSS, Payload: `<script>alert(1)</script>`, Contexts: []string{"html_body"}, Confidence: 0.85, Severity: model.High, ExecutionVerified: true},
		{URL: "http://a.com/p?q=2", Parameter: "q", Type: model.ReflectedXSS, Payload: `<img src=x onerror=alert(1)>`, Contexts: []string{"html_body"}, Confidence: 0.9, Severity: model.High},
	}
	result := AggregateFindings(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(result))
	}
	if !result[0].ExecutionVerified {
		t.Error("verified variant should promote the aggregated finding")
	}
}
