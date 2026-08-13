package crawler

import (
	"testing"
	"time"
)

func TestRenderTimeoutDefault(t *testing.T) {
	tests := []time.Duration{0, -1, -5 * time.Second}
	for _, in := range tests {
		if got := renderTimeoutOrDefault(in); got != renderTimeout {
			t.Errorf("renderTimeoutOrDefault(%v) = %v, want %v", in, got, renderTimeout)
		}
	}
}

func TestRenderTimeoutCustom(t *testing.T) {
	custom := 5 * time.Second
	if got := renderTimeoutOrDefault(custom); got != custom {
		t.Errorf("renderTimeoutOrDefault(%v) = %v, want %v", custom, got, custom)
	}
}

func TestToNetworkHeaders_Empty(t *testing.T) {
	h := toNetworkHeaders(nil)
	if len(h) != 0 {
		t.Errorf("expected empty headers, got %d entries", len(h))
	}
}

func TestToNetworkHeaders_Populated(t *testing.T) {
	in := map[string]string{
		"Authorization": "Bearer token123",
		"X-Custom":      "中文值",
	}
	h := toNetworkHeaders(in)
	if len(h) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(h))
	}
	if h["Authorization"] != "Bearer token123" {
		t.Errorf("Authorization = %v, want Bearer token123", h["Authorization"])
	}
	if h["X-Custom"] != "中文值" {
		t.Errorf("X-Custom = %v, want 中文值", h["X-Custom"])
	}
}

func TestExtractForms_BasicGETForm(t *testing.T) {
	html := `<html><body><form action="/search"><input name="q" type="text"><input type="submit"></form></body></html>`
	forms, err := extractForms(html, "http://example.com/")
	if err != nil {
		t.Fatalf("extractForms: %v", err)
	}
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	f := forms[0]
	if f.Method != "GET" {
		t.Errorf("method = %q, want GET", f.Method)
	}
	if len(f.Inputs) != 1 || f.Inputs[0] != "q" {
		t.Errorf("inputs = %v, want [q]", f.Inputs)
	}
}

func TestExtractForms_PostForm(t *testing.T) {
	html := `<html><body><form action="/submit" method="post"><input name="msg"><button type="submit">Send</button></form></body></html>`
	forms, err := extractForms(html, "http://example.com/")
	if err != nil {
		t.Fatalf("extractForms: %v", err)
	}
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if forms[0].Method != "POST" {
		t.Errorf("method = %q, want POST", forms[0].Method)
	}
	if len(forms[0].Inputs) != 1 || forms[0].Inputs[0] != "msg" {
		t.Errorf("inputs = %v, want [msg]", forms[0].Inputs)
	}
}

func TestExtractForms_SkipsSubmitTypes(t *testing.T) {
	html := `<form action="/x"><input name="a"><input type="submit" name="s"><input type="button" name="b"><input type="image" name="i"><input type="reset" name="r"></form>`
	forms, err := extractForms(html, "http://example.com/")
	if err != nil {
		t.Fatalf("extractForms: %v", err)
	}
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if len(forms[0].Inputs) != 1 || forms[0].Inputs[0] != "a" {
		t.Errorf("inputs = %v, want [a] (submit/button/image/reset excluded)", forms[0].Inputs)
	}
}

func TestExtractForms_NoForms(t *testing.T) {
	forms, err := extractForms("<html><body><p>no forms here</p></body></html>", "http://example.com/")
	if err != nil {
		t.Fatalf("extractForms: %v", err)
	}
	if len(forms) != 0 {
		t.Errorf("expected 0 forms, got %d", len(forms))
	}
}
