package analyze

import "testing"

func TestDetectFilterProfile(t *testing.T) {
	tests := []struct {
		name string
		body string
		check func(*FilterProfile) bool
	}{
		{
			name: "strips angle brackets",
			body: `value="xsscan'()=onerror=alert(javascript:"`,
			check: func(p *FilterProfile) bool {
				return p != nil && p.StripsAngleBrackets && p.AllowsQuotes()
			},
		},
		{
			name: "encodes angle brackets",
			body: `value="xsscan&lt;&gt;&quot;'()=onerror=alert(javascript:"`,
			check: func(p *FilterProfile) bool {
				return p != nil && p.EncodesAngleBrackets
			},
		},
		{
			name: "encodes quotes",
			body: `value="xsscan<>"&quot;'()=onerror=alert(javascript:"`,
			check: func(p *FilterProfile) bool {
				return p != nil && p.EncodesQuotes
			},
		},
		{
			name: "filters event handlers",
			body: `value="xsscan<>"'()=o_nerror=alert(javascript:"`,
			check: func(p *FilterProfile) bool {
				return p != nil && p.FiltersEventHandlers
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
	p := &FilterProfile{FiltersKeywords: map[string]bool{}}
	if !p.AllowsAngleBrackets() || !p.AllowsQuotes() {
		t.Error("empty profile should allow both")
	}
	p.StripsAngleBrackets = true
	if p.AllowsAngleBrackets() {
		t.Error("stripped brackets should not allow angle brackets")
	}
	p.EncodesQuotes = true
	if p.AllowsQuotes() {
		t.Error("encoded quotes should not allow quotes")
	}
}
