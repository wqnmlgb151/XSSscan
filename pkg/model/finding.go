package model

import "time"

type VulnerabilityType string

const (
	ReflectedXSS VulnerabilityType = "reflected_xss"
	StoredXSS    VulnerabilityType = "stored_xss"
	DOMXSS       VulnerabilityType = "dom_xss"
	BlindXSS     VulnerabilityType = "blind_xss"
	SelfXSS      VulnerabilityType = "self_xss"
)

type Evidence struct {
	Reflection     string `json:"reflection"`
	Context        string `json:"context"`
	ScreenshotPath string `json:"screenshot_path,omitempty"`
}

// CSPBypass represents a detected Content-Security-Policy bypass that can
// be exploited to execute XSS despite the presence of a CSP header.
type CSPBypass struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Exploit     string `json:"exploit"`
}

type Finding struct {
	ID                  string            `json:"id"`
	Type                VulnerabilityType `json:"type"`
	Severity            Severity          `json:"severity"`
	Confidence          float64           `json:"confidence"`
	URL                 string            `json:"url"`
	Parameter           string            `json:"parameter"`
	ParamType           ParamType         `json:"param_type"`
	Payload             string            `json:"payload"`
	Payloads            []string          `json:"payloads,omitempty"` // all payload variants after same-param aggregation
	Contexts            []string          `json:"contexts"`
	Evidence            Evidence          `json:"evidence"`
	Description         string            `json:"description"`
	Remediation         string            `json:"remediation"`
	CWE                 string            `json:"cwe,omitempty"`
	References          []string          `json:"references,omitempty"`
	Timestamp           time.Time         `json:"timestamp"`
	RawRequest          string            `json:"raw_request,omitempty"`
	RawResponse         string            `json:"raw_response,omitempty"`
	ExecutionVerified   bool              `json:"execution_verified,omitempty"`
	ExecutionConfidence float64           `json:"execution_confidence,omitempty"`
	ScreenshotPath      string            `json:"screenshot_path,omitempty"`
	CSPBypasses         []CSPBypass       `json:"csp_bypasses,omitempty"`
}
