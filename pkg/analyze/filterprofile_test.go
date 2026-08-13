package analyze

import "testing"

func TestDetectFilterProfile(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		check func(*FilterProfile) bool
	}{
		{
			name: "strips angle brackets",
			body: `value="xsscan'()=onerror=alert(javascript:"`,
			check: func(p *FilterProfile) bool {
				return p != nil && p.StripsAngleBrackets && p.AllowsDoubleQuote() && p.AllowsSingleQuote()
			},
		},
		{
			name: "encodes angle brackets",
			body: `value="xsscan&lt;&gt;"'()=onerror=alert(javascript:"`,
			check: func(p *FilterProfile) bool {
				return p != nil && p.EncodesAngleBrackets
			},
		},
		{
			name: "encodes double quotes only",
			body: `value="xsscan<>"&quot;'()=onerror=alert(javascript:"`,
			check: func(p *FilterProfile) bool {
				return p != nil && p.EncodesDoubleQuote && !p.EncodesSingleQuote &&
					p.AllowsSingleQuote() && !p.AllowsDoubleQuote()
			},
		},
		{
			name: "encodes single quotes only",
			body: `value="xsscan<>"&#39;()=onerror=alert(javascript:"`,
			check: func(p *FilterProfile) bool {
				return p != nil && !p.EncodesDoubleQuote && p.EncodesSingleQuote &&
					p.AllowsDoubleQuote() && !p.AllowsSingleQuote()
			},
		},
		{
			name: "page markup does not skew angle detection",
			body: `<html><body>xsscan<>"'()=onerror=alert(javascript:</body></html>`,
			check: func(p *FilterProfile) bool {
				return p != nil && !p.EncodesAngleBrackets && !p.StripsAngleBrackets &&
					p.AllowsAngleBrackets() && p.AllowsDoubleQuote() && p.AllowsSingleQuote()
			},
		},
		{
			name: "no reflection returns nil",
			body: `safe page content`,
			check: func(p *FilterProfile) bool {
				return p == nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := DetectFilterProfile(tt.body)
			if !tt.check(p) {
				t.Errorf("DetectFilterProfile(%q) = %+v, check failed", tt.body, p)
			}
		})
	}
}

func TestFilterProfile_Allows(t *testing.T) {
	p := &FilterProfile{}
	if !p.AllowsAngleBrackets() || !p.AllowsDoubleQuote() || !p.AllowsSingleQuote() {
		t.Error("empty profile should allow all")
	}
	p.StripsAngleBrackets = true
	if p.AllowsAngleBrackets() {
		t.Error("stripped brackets should not allow angle brackets")
	}
	p.EncodesDoubleQuote = true
	if p.AllowsDoubleQuote() {
		t.Error("encoded double quotes should not allow double-quote breakout")
	}
	if !p.AllowsSingleQuote() {
		t.Error("double-quote encoding must not affect single-quote allowance")
	}
}
