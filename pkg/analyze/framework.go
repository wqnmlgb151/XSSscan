package analyze

import (
	"net/http"
	"regexp"
)

// FrameworkInfo holds detected frontend framework information
type FrameworkInfo struct {
	Name       string  `json:"name"`
	Version    string  `json:"version,omitempty"`
	Confidence float64 `json:"confidence"`
}

// FrameworkDetector identifies frontend frameworks from HTTP responses
type FrameworkDetector struct {
	signatures []FrameworkSignature
}

type FrameworkSignature struct {
	Name       string
	Indicators []FrameworkIndicator
}

type FrameworkIndicator struct {
	Pattern *regexp.Regexp
}

// NewFrameworkDetector creates a detector with pre-compiled signatures
func NewFrameworkDetector() *FrameworkDetector {
	return &FrameworkDetector{
		signatures: []FrameworkSignature{
			{
				Name: "React",
				Indicators: []FrameworkIndicator{
					{Pattern: regexp.MustCompile(`react-root`)},
					{Pattern: regexp.MustCompile(`react-dom`)},
					{Pattern: regexp.MustCompile(`data-reactroot`)},
					{Pattern: regexp.MustCompile(`__REACT_DEVTOOLS`)},
				},
			},
			{
				Name: "Vue",
				Indicators: []FrameworkIndicator{
					{Pattern: regexp.MustCompile(`vue(\.min)?\.js`)},
					{Pattern: regexp.MustCompile(`data-v-[a-f0-9]{8}`)},
					{Pattern: regexp.MustCompile(`__VUE__`)},
					{Pattern: regexp.MustCompile(`v-cloak`)},
				},
			},
			{
				Name: "Angular",
				Indicators: []FrameworkIndicator{
					{Pattern: regexp.MustCompile(`ng-version`)},
					{Pattern: regexp.MustCompile(`angular(\.min)?\.js`)},
					{Pattern: regexp.MustCompile(`\[ng-`)},
					{Pattern: regexp.MustCompile(`ng-binding`)},
					// AngularJS 1.x specific indicators
					{Pattern: regexp.MustCompile(`ng-app`)},
					{Pattern: regexp.MustCompile(`ng-controller`)},
					{Pattern: regexp.MustCompile(`angular\.module`)},
					{Pattern: regexp.MustCompile(`\bng-[a-z]+=`)},
				},
			},
			{
				Name: "Svelte",
				Indicators: []FrameworkIndicator{
					{Pattern: regexp.MustCompile(`svelte-[a-z0-9]{4,8}`)},
					{Pattern: regexp.MustCompile(`__svelte`)},
				},
			},
			{
				Name: "Next.js",
				Indicators: []FrameworkIndicator{
					{Pattern: regexp.MustCompile(`__NEXT_DATA__`)},
					{Pattern: regexp.MustCompile(`/_next/static/`)},
				},
			},
			{
				Name: "Nuxt.js",
				Indicators: []FrameworkIndicator{
					{Pattern: regexp.MustCompile(`__NUXT__`)},
					{Pattern: regexp.MustCompile(`/_nuxt/`)},
				},
			},
			{
				Name: "jQuery",
				Indicators: []FrameworkIndicator{
					{Pattern: regexp.MustCompile(`jquery(\.min)?\.js`)},
					{Pattern: regexp.MustCompile(`jQuery\.fn`)},
				},
			},
		},
	}
}

// Detect scans the response for framework signatures
func (fd *FrameworkDetector) Detect(resp *http.Response, body string) []FrameworkInfo {
	seen := make(map[string]int)
	total := make(map[string]int)

	for _, sig := range fd.signatures {
		total[sig.Name] = len(sig.Indicators)
		for _, ind := range sig.Indicators {
			if ind.Pattern.MatchString(body) {
				seen[sig.Name]++
			}
		}
	}

	var results []FrameworkInfo
	for name, matchCount := range seen {
		if matchCount > 0 {
			// matchCount ≤ total[name] by construction, so confidence ∈ (0, 1]
			confidence := float64(matchCount) / float64(total[name])
			results = append(results, FrameworkInfo{
				Name:       name,
				Confidence: confidence,
			})
		}
	}
	return results
}

// RiskInfo returns whether the framework has DOM XSS risk and its sinks
func (f *FrameworkInfo) RiskInfo() (bool, []string) {
	switch f.Name {
	case "React":
		return true, []string{"dangerouslySetInnerHTML", "innerHTML"}
	case "Vue":
		return true, []string{"v-html", "innerHTML"}
	case "Angular":
		return true, []string{"[innerHTML]", "bypassSecurityTrustHtml"}
	case "Svelte":
		return true, []string{"@html", "innerHTML"}
	}
	return false, nil
}

