package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
)

// generateSARIF produces a SARIF 2.1.0 report for integration with GitHub Code Scanning,
// Azure DevOps, and other SARIF-compatible platforms.
func (r *Reporter) generateSARIF(data *ScanData) ([]byte, error) {
	run := sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{
				Name:           "xsscan",
				InformationURI: "https://github.com/xsscan/xsscan",
				Rules:          []sarifRule{},
			},
		},
		Results: []sarifResult{},
	}

	ruleMap := make(map[string]sarifRule)
	for _, f := range data.Findings {
		ruleID := fmt.Sprintf("xsscan/%s", strings.ToLower(f.Type))
		if _, ok := ruleMap[ruleID]; !ok {
			ruleMap[ruleID] = sarifRule{
				ID:   ruleID,
				Name: f.Type,
				ShortDescription: sarifMessage{
					Text: fmt.Sprintf("Cross-Site Scripting (%s)", f.Type),
				},
				FullDescription: sarifMessage{
					Text: f.Description,
				},
				DefaultConfiguration: sarifConfiguration{
					Level: sarifLevel(f.Severity),
				},
				HelpURI: "https://owasp.org/www-community/attacks/xss/",
			}
		}

		result := sarifResult{
			RuleID: ruleID,
			Level:  sarifLevel(f.Severity),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s in parameter '%s' (confidence: %.0f%%)", f.Description, f.Parameter, f.Confidence*100),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.URL,
						},
						Region: sarifRegion{
							StartLine: 1,
						},
					},
				},
			},
			Properties: sarifProperties{
				Tags:       f.Contexts,
				Payload:    f.Payload,
				Severity:   f.Severity,
				CSPBypasses: formatCSPBypassesForSARIF(f.CSPBypasses),
			},
		}
		run.Results = append(run.Results, result)
	}

	for _, rule := range ruleMap {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
	}

	sarif := sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []sarifRun{run},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// sarifLevel maps severity strings to SARIF levels.
func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "warning"
	}
}

// SARIF 2.1.0 data structures (all unexported — used only within this package)

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name,omitempty"`
	ShortDescription     sarifMessage       `json:"shortDescription,omitempty"`
	FullDescription      sarifMessage       `json:"fullDescription,omitempty"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration,omitempty"`
	HelpURI              string             `json:"helpUri,omitempty"`
}

type sarifConfiguration struct {
	Level string `json:"level,omitempty"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level,omitempty"`
	Message    sarifMessage     `json:"message"`
	Locations  []sarifLocation  `json:"locations,omitempty"`
	Properties sarifProperties  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type sarifProperties struct {
	Tags        []string `json:"tags,omitempty"`
	Payload     string   `json:"payload,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	CSPBypasses string   `json:"csp_bypasses,omitempty"`
}

// formatCSPBypassesForSARIF converts CSP bypass entries to a single
// newline-separated string for SARIF property storage.
func formatCSPBypassesForSARIF(bypasses []model.CSPBypass) string {
	if len(bypasses) == 0 {
		return ""
	}
	var parts []string
	for _, b := range bypasses {
		parts = append(parts, fmt.Sprintf("%s: %s (exploit: %s)", b.Type, b.Description, b.Exploit))
	}
	return strings.Join(parts, "\n")
}

// generateJUnit produces a JUnit XML report for CI/CD pipeline integration.
func (r *Reporter) generateJUnit(data *ScanData) string {
	var b strings.Builder
	timestamp := time.Now().Format(time.RFC3339)
	findings := len(data.Findings)

	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	fmt.Fprintf(&b, `<testsuites name="xsscan" tests="%d" failures="%d" time="%d">`+"\n",
		findings, findings, data.Duration)
	fmt.Fprintf(&b, `  <testsuite name="xsscan-xss" tests="%d" failures="%d" timestamp="%s">`+"\n",
		findings, findings, timestamp)

	for _, f := range data.Findings {
		safeDesc := html.EscapeString(f.Description)
		safePayload := html.EscapeString(f.Payload)
		safeParam := html.EscapeString(f.Parameter)
		safeURL := html.EscapeString(f.URL)

		fmt.Fprintf(&b, `    <testcase name="%s" classname="%s">`+"\n",
			safeDesc, safeURL)
		fmt.Fprintf(&b, `      <failure message="%s" type="%s">`+"\n",
			safeDesc, f.Type)
		fmt.Fprintf(&b, "        Parameter: %s\n", safeParam)
		fmt.Fprintf(&b, "        Payload: %s\n", safePayload)
		fmt.Fprintf(&b, "        Severity: %s\n", f.Severity)
		fmt.Fprintf(&b, "        Confidence: %.0f%%\n", f.Confidence*100)
		fmt.Fprintf(&b, "        Contexts: %s\n", strings.Join(f.Contexts, ", "))
		fmt.Fprintf(&b, "      </failure>\n")
		fmt.Fprintf(&b, "    </testcase>\n")
	}

	b.WriteString("  </testsuite>\n")
	b.WriteString("</testsuites>\n")
	return b.String()
}

