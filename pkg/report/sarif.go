package report

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

// generateSARIF produces a SARIF 2.1.0 report for integration with GitHub Code Scanning,
// Azure DevOps, and other SARIF-compatible platforms.
func (r *Reporter) generateSARIF(data *ScanData) ([]byte, error) {
	run := sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{
				Name:           "xsscan",
				InformationURI: "https://github.com/wqnmlgb151/XSSscan",
				Rules:          []sarifRule{},
			},
		},
		Results: []sarifResult{},
	}

	run.Invocations = []sarifInvocation{{ExecutionSuccessful: reportStatus(data) == model.ScanCompleted, Properties: map[string]interface{}{"status": reportStatus(data), "issues": data.Issues, "modules": data.Modules, "coverage": data.Coverage, "requests_sent": data.RequestsSent, "payloads_sent": data.PayloadsSent, "errors": data.Errors, "cross_module": data.CrossModule}}}
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
				ExecutionVerified:   f.ExecutionVerified,
				ExecutionConfidence: f.ExecutionConfidence,
				Evidence:            f.Evidence,
				RawRequest:          f.RawRequest, RawResponse: f.RawResponse,
				Tags:        f.Contexts,
				Payload:     f.Payload,
				Payloads:    f.Payloads,
				Severity:    f.Severity,
				CSPBypasses: formatCSPBypassesForSARIF(f.CSPBypasses),
			},
		}
		run.Results = append(run.Results, result)
	}

	for _, rule := range ruleMap {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
	}
	sort.Slice(run.Tool.Driver.Rules, func(i, j int) bool { return run.Tool.Driver.Rules[i].ID < run.Tool.Driver.Rules[j].ID })

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

type sarifInvocation struct {
	ExecutionSuccessful bool                   `json:"executionSuccessful"`
	Properties          map[string]interface{} `json:"properties"`
}

type sarifRun struct {
	Invocations []sarifInvocation `json:"invocations"`
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
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
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level,omitempty"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties sarifProperties `json:"properties,omitempty"`
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
	ExecutionVerified   bool           `json:"execution_verified"`
	ExecutionConfidence float64        `json:"execution_confidence"`
	RawRequest          string         `json:"raw_request,omitempty"`
	RawResponse         string         `json:"raw_response,omitempty"`
	Evidence            model.Evidence `json:"evidence,omitempty"`
	Tags                []string       `json:"tags,omitempty"`
	Payload             string         `json:"payload,omitempty"`
	Payloads            []string       `json:"payloads,omitempty"`
	Severity            string         `json:"severity,omitempty"`
	CSPBypasses         string         `json:"csp_bypasses,omitempty"`
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
	errorCount := 0
	if reportStatus(data) != model.ScanCompleted {
		errorCount = 1
	}

	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	fmt.Fprintf(&b, `<testsuites name="xsscan" tests="%d" failures="%d" errors="%d" time="%.3f">`+"\n",
		findings+errorCount, findings, errorCount, float64(data.Duration)/1000)
	fmt.Fprintf(&b, `  <testsuite name="xsscan-xss" tests="%d" failures="%d" errors="%d" timestamp="%s" time="%.3f">`+"\n",
		findings+errorCount, findings, errorCount, timestamp, float64(data.Duration)/1000)
	{
		b.WriteString("<system-out>")
		fmt.Fprintf(&b, "Status: %s\nRequests: %d | Payloads: %d | Errors: %d\n", xmlText(string(reportStatus(data))), data.RequestsSent, data.PayloadsSent, data.Errors)
		for _, coverage := range data.Coverage {
			fmt.Fprintf(&b, "Coverage: %s\n", xmlText(coverage.String()))
		}
		for _, observation := range data.CrossModule {
			fmt.Fprintf(&b, "Observation: %s / %s / %s: %s\n", xmlText(observation.Module), xmlText(string(observation.Kind)), xmlText(observation.Subject), xmlText(observation.Detail))
		}
		for _, module := range data.Modules {
			fmt.Fprintf(&b, "Module: %s / %s / %s — %s | Requests: %d | Candidates: %d | Findings: %d\n", xmlText(module.Type), xmlText(module.Target), xmlText(string(module.Status)), xmlText(module.Reason), module.Requests, module.Candidates, module.Findings)
		}
		b.WriteString("</system-out>\n")
	}

	if errorCount > 0 {
		fmt.Fprintf(&b, `    <testcase name="scan completion"><error message="%s">`, xmlText(string(reportStatus(data))))
		for _, issue := range data.Issues {
			fmt.Fprintf(&b, "%s / %s: %s\n", xmlText(issue.Target), xmlText(issue.Stage), xmlText(issue.Message))
			if issue.HTTP != nil {
				fmt.Fprintf(&b, "%s\n%s\n", xmlText(issue.HTTP.Request), xmlText(issue.HTTP.Response))
			}
		}
		b.WriteString("</error></testcase>\n")
	}
	for _, f := range data.Findings {
		safeDesc := xmlText(f.Description)
		safePayload := xmlText(f.Payload)
		safeParam := xmlText(f.Parameter)
		safeURL := xmlText(f.URL)

		fmt.Fprintf(&b, `    <testcase name="%s" classname="%s">`+"\n",
			safeDesc, safeURL)
		fmt.Fprintf(&b, `      <failure message="%s" type="%s">`+"\n",
			safeDesc, xmlText(f.Type))
		fmt.Fprintf(&b, "        Parameter: %s\n", safeParam)
		fmt.Fprintf(&b, "        Payload: %s\n", safePayload)
		for _, field := range evidenceFields(f.Evidence) {
			fmt.Fprintf(&b, "        %s: %s\n", xmlText(field[0]), xmlText(field[1]))
		}
		// Variants excluding the primary payload (already printed above)
		for _, v := range f.Payloads {
			if v != f.Payload {
				fmt.Fprintf(&b, "        Variant: %s\n", xmlText(v))
			}
		}
		fmt.Fprintf(&b, "        Raw Request: %s\n        Raw Response: %s\n", strings.ReplaceAll(xmlText(f.RawRequest), "\r", "&#13;"), strings.ReplaceAll(xmlText(f.RawResponse), "\r", "&#13;"))
		fmt.Fprintf(&b, "        Severity: %s\n", xmlText(f.Severity))
		fmt.Fprintf(&b, "        Confidence: %.0f%%\n", f.Confidence*100)
		fmt.Fprintf(&b, "        Execution verified: %t\n", f.ExecutionVerified)
		fmt.Fprintf(&b, "        Contexts: %s\n", xmlText(strings.Join(f.Contexts, ", ")))
		fmt.Fprintf(&b, "      </failure>\n")
		fmt.Fprintf(&b, "    </testcase>\n")
	}

	b.WriteString("  </testsuite>\n")
	b.WriteString("</testsuites>\n")
	return b.String()
}

func xmlText(raw string) string {
	if model.NeedsBinaryEvidence(raw) {
		return "[base64]" + base64.StdEncoding.EncodeToString([]byte(raw))
	}
	return strings.ReplaceAll(html.EscapeString(raw), "\r", "&#13;")
}
