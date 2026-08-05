package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

// init is in engine_coverage_test.go — do not duplicate

func TestGetProbeForContext(t *testing.T) {
	tests := []struct{
		name string
		ct ctx.ContextType
		wantOK bool
		wantProbe string
}{
		{"html_body", ctx.ContextHTMLBody, true, "<xsscan>"},
		{"html_comment", ctx.ContextHTMLComment, true, "--><xsscan><!--"},
		{"html_tag", ctx.ContextHTMLTag, true, "xsscan"},
		{"html_attr_name", ctx.ContextHTMLAttrName, true, "xsscan"},
		{"html_attr_value", ctx.ContextHTMLAttrValue, true, " xsscan>"},
		{"html_entity", ctx.ContextHTMLEntity, true, "xsscan"},
		{"js_string", ctx.ContextJSString, true, jsStringProbeValue},
		{"js_comment", ctx.ContextJSComment, true, "/*xsscan*/"},
		{"js_block", ctx.ContextJSBlock, true, "</script><xsscan>"},
		{"css_value", ctx.ContextCSSValue, true, "xsscan"},
		{"css_block", ctx.ContextCSSBlock, true, "</style><xsscan><style>"},
		{"url_attr", ctx.ContextURLAttr, true, "javascript:xsscan"},
		{"template", ctx.ContextTemplate, true, "{{xsscan}}"},
		{"svg_container", ctx.ContextSVGContainer, true, "<xsscan>"},
		{"mathml_container", ctx.ContextMathMLContainer, true, "<xsscan>"},
		{"json_value", ctx.ContextJSONValue, true, jsonProbeValue},
		{"unknown", ctx.ContextUnknown, false, ""},
		{"multi", ctx.ContextMulti, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe, ok := GetProbeForContext(tt.ct)
			if ok != tt.wantOK {
				t.Errorf("GetProbeForContext(%s) ok=%v, want %v", tt.name, ok, tt.wantOK)
			}
			if ok && probe.Probe != tt.wantProbe {
				t.Errorf("GetProbeForContext(%s) probe=%q, want %q", tt.name, probe.Probe, tt.wantProbe)
			}
		})
	}
}

func TestValidateUnescapedProbe(t *testing.T) {
	tests := []struct{
		name string
		probe string
		body string
		want bool
}{
		{"raw probe present", "<xsscan>", "<html><body><xsscan></body></html>", true},
		{"escaped probe", "<xsscan>", "<html><body>&lt;xsscan&gt;</body></html>", false},
		{"probe absent", "<xsscan>", "<html><body>safe</body></html>", false},
		{"simple text present", "xsscan", "<html><body>xsscan</body></html>", true},
		{"simple text absent", "xsscan", "<html><body>safe</body></html>", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := validateUnescapedProbe(tt.probe)
			got := validator(tt.body)
			if got != tt.want {
				t.Errorf("validateUnescapedProbe(%q)(%q) = %v, want %v", tt.probe, tt.body, got, tt.want)
			}
		})
	}
}

func TestProbeValues(t *testing.T) {
	// 0x27 = single quote, 0x2F 0x2F = // (JS comment closer)
	wantJS := "';xsscan//"
	if jsStringProbeValue != wantJS {
		t.Errorf("jsStringProbeValue = %q, want %q", jsStringProbeValue, wantJS)
	}
	// 0x22 = double quote
	wantJSON := `"xsscan"`
	if jsonProbeValue != wantJSON {
		t.Errorf("jsonProbeValue = %q, want %q", jsonProbeValue, wantJSON)
	}
}

func TestRunContextProbe(t *testing.T) {
	ssrfguard.AllowPrivate = true
	tests := []struct {
		name     string
		handler  http.HandlerFunc
		ct       ctx.ContextType
		escaped  bool
		wantPass bool
	}{
		{
			name: "vulnerable html body passes probe",
			handler: func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query().Get("q")
				w.Write([]byte("<html><body>" + q + "</body></html>"))
			},
			ct:       ctx.ContextHTMLBody,
			escaped:  false,
			wantPass: true,
		},
		{
			name: "escaped reflection fails probe",
			handler: func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query().Get("q")
				safe := strings.ReplaceAll(q, "<", "&lt;")
				safe = strings.ReplaceAll(safe, ">", "&gt;")
				w.Write([]byte("<html><body>" + safe + "</body></html>"))
			},
			ct:       ctx.ContextHTMLBody,
			escaped:  false,
			wantPass: false,
		},
		{
			name: "non-exploitable context fails open",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("<html><body>safe</body></html>"))
			},
			ct:       ctx.ContextHTMLComment,
			escaped:  true,
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			target := model.Target{
				URL:    server.URL + "/?q=test",
				Method: "GET",
			}
			parameter := model.Parameter{
				Name: "q",
				Type: model.ParamQuery,
			}
			injection := model.InjectionPoint{
				Target:    target,
				Parameter: parameter,
				Contexts: []ctx.Context{
					{Type: tt.ct, Escaped: tt.escaped},
				},
			}

			engine := newTestEngine(server.URL)
			got := engine.runContextProbe(context.Background(), injection, "127.0.0.1")
			if (got != nil) != tt.wantPass {
				t.Errorf("runContextProbe(%s) = %v, want %v", tt.name, got != nil, tt.wantPass)
			}
		})
	}
}

func TestRunContextProbe_MultipleContextsPicksBest(t *testing.T) {
	// When multiple exploitable contexts are present, the one with the highest
	// priority should be selected for probing. Here HTMLBody (priority 10)
	// beats JSString (priority 5).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Reflect raw (vulnerable) — probe should pass
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/?q=test", Method: "GET"}
	parameter := model.Parameter{Name: "q", Type: model.ParamQuery}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: parameter,
		Contexts: []ctx.Context{
			{Type: ctx.ContextHTMLBody, Priority: 10},
			{Type: ctx.ContextJSString, Priority: 5},
		},
	}

	got := engine.runContextProbe(context.Background(), injection, "127.0.0.1")
	if got == nil {
		t.Error("Expected probe to pass (highest-priority exploitable context should be tested)")
	}
}

func TestRunContextProbe_NoContextsFailOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("empty"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/?q=test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts:  []ctx.Context{}, // no contexts at all
	}

	got := engine.runContextProbe(context.Background(), injection, "127.0.0.1")
	if got == nil {
		t.Error("Expected fail-open when no contexts are present")
	}
}

func TestRunContextProbe_OnlyNonExploitableFailOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("safe"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/?q=test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts: []ctx.Context{
			{Type: ctx.ContextUnknown, Escaped: true},
		},
	}

	got := engine.runContextProbe(context.Background(), injection, "127.0.0.1")
	if got == nil {
		t.Error("Expected fail-open when only non-exploitable contexts are present")
	}
}

func TestRunContextProbe_JSStringContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Reflect inside a JS string without escaping
		w.Write([]byte("<script>var x = '" + q + "';</script>"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/?q=test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts: []ctx.Context{
			{Type: ctx.ContextJSString, Priority: 5},
		},
	}

	got := engine.runContextProbe(context.Background(), injection, "127.0.0.1")
	if got == nil {
		t.Error("Expected JS string probe to pass when reflection is unescaped")
	}
}

func TestRunContextProbe_JSONContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Reflect inside a JSON string value
		w.Write([]byte("{\"data\": \"" + q + "\"}"))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/?q=test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts: []ctx.Context{
			{Type: ctx.ContextJSONValue, Priority: 5},
		},
	}

	got := engine.runContextProbe(context.Background(), injection, "127.0.0.1")
	if got == nil {
		t.Error("Expected JSON probe to pass when reflection is unescaped")
	}
}

func TestRunContextProbe_NetworkErrorFailOpen(t *testing.T) {
	// Use a server URL that refuses connections — probe should fail open
	engine := newTestEngine("http://127.0.0.1:1") // port 1 should be unreachable
	target := model.Target{URL: "http://127.0.0.1:1/?q=test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
		Contexts: []ctx.Context{
			{Type: ctx.ContextHTMLBody, Priority: 10},
		},
	}

	got := engine.runContextProbe(context.Background(), injection, "127.0.0.1")
	if got == nil {
		t.Error("Expected fail-open on network error")
	}
}

// --- Individual validator function tests ---

func TestValidateCommentBreakout(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"broke out", "<html>--><xsscan><!--</html>", true},
		{"no breakout — raw tag absent", "<!-- comment content -->", false},
		{"empty body", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateCommentBreakout(tt.body); got != tt.want {
				t.Errorf("validateCommentBreakout(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestValidateAttrBreakout(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"attr escaped", `value=" xsscan><script>`, true},
		{"attr intact", `value="xsscan"`, false},
		{"empty body", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateAttrBreakout(tt.body); got != tt.want {
				t.Errorf("validateAttrBreakout(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestValidateURLBreakout(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"javascript protocol", `<a href="javascript:alert(1)">`, true},
		{"JavaScript mixed case", `<a href="JavaScript:alert(1)">`, true},
		{"https protocol", `<a href="https://example.com">`, false},
		{"empty body", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateURLBreakout(tt.body); got != tt.want {
				t.Errorf("validateURLBreakout(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestValidateUnescapedProbeWithSpecialChars(t *testing.T) {
	// Test the escaped-form detection branch
	validator := validateUnescapedProbe("<xsscan>")

	tests := []struct {
		name string
		body string
		want bool
	}{
		{"raw present", "<div><xsscan></div>", true},
		{"fully escaped", "&lt;xsscan&gt;", false},
		{"partially escaped LT", "&lt;xsscan>", false},
		{"absent", "<div>safe</div>", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validator(tt.body); got != tt.want {
				t.Errorf("validator(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestSendProbeRequest(t *testing.T) {
	ssrfguard.AllowPrivate = true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Write([]byte("probe response: " + q))
	}))
	defer server.Close()

	engine := newTestEngine(server.URL)
	target := model.Target{URL: server.URL + "/?q=test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}

	body, err := engine.sendProbeRequest(context.Background(), injection, "PROBE_VALUE", "127.0.0.1")
	if err != nil {
		t.Fatalf("sendProbeRequest failed: %v", err)
	}
	if body != "probe response: PROBE_VALUE" {
		t.Errorf("Expected 'probe response: PROBE_VALUE', got %q", body)
	}
}

func TestSendProbeRequestInjectError(t *testing.T) {
	engine := newTestEngine("http://example.com")
	// Use an unsupported parameter type to trigger injectPayload error
	target := model.Target{URL: "http://example.com/test", Method: "GET"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "x", Type: model.ParamType("unsupported")},
	}

	_, err := engine.sendProbeRequest(context.Background(), injection, "probe", "127.0.0.1")
	if err == nil {
		t.Fatal("Expected error for unsupported parameter type")
	}
}
