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
	Diagnostics         []string      `json:"diagnostics,omitempty"`
	AnalysisMethod      string        `json:"analysis_method,omitempty"`
	ParseError          string        `json:"parse_error,omitempty"`
	HTTP                *HTTPExchange `json:"http,omitempty"`
	SubmissionHTTP      *HTTPExchange `json:"submission_http,omitempty"`
	VerificationPayload string        `json:"verification_payload,omitempty"`
	VerificationError   string        `json:"verification_error,omitempty"`
	DialogMessage       string        `json:"dialog_message,omitempty"`
	TriggerURL          string        `json:"trigger_url,omitempty"`
	DetectionMethod     string        `json:"detection_method,omitempty"`
	Interaction         string        `json:"interaction,omitempty"`
	Reflection          string        `json:"reflection"`
	Context             string        `json:"context"`
	ScreenshotPath      string        `json:"screenshot_path,omitempty"`
	DataFlow            []JSDataFlow  `json:"data_flow,omitempty"`
}

// JSDataFlow describes a static hypothesis attached to a matching runtime sink.
// Offsets are bytes in the inline script text, not offsets in the HTML document.
type JSDataFlow struct {
	Source      string `json:"source"`
	Key         string `json:"key,omitempty"`
	Sink        string `json:"sink"`
	ScriptIndex int    `json:"script_index"`
	SourceStart int    `json:"source_start"`
	SourceEnd   int    `json:"source_end"`
	SinkStart   int    `json:"sink_start"`
	SinkEnd     int    `json:"sink_end"`
}

// CSPBypass represents a detected Content-Security-Policy bypass that can
// be exploited to execute XSS despite the presence of a CSP header.
type CSPBypass struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Exploit     string `json:"exploit"`
}

type Finding struct {
	ID         string            `json:"id"`
	Type       VulnerabilityType `json:"type"`
	Severity   Severity          `json:"severity"`
	Confidence float64           `json:"confidence"`
	URL        string            `json:"url"`
	Parameter  string            `json:"parameter"`
	ParamType  ParamType         `json:"param_type"`
	// ReflectionPath identifies the candidate's planning bucket using request
	// identity and a reflection anchor. Same-type positions may share the first
	// anchor; this is not proof of which position executed. Empty paths use the
	// legacy parameter/context grouping. Execution evidence belongs to the
	// checked payload, not every position or alternative in its bucket.
	ReflectionPath      string      `json:"reflection_path,omitempty"`
	Payload             string      `json:"payload"`
	Payloads            []string    `json:"payloads,omitempty"` // all payload variants after same-param aggregation
	Contexts            []string    `json:"contexts"`
	Evidence            Evidence    `json:"evidence"`
	Description         string      `json:"description"`
	Remediation         string      `json:"remediation"`
	CWE                 string      `json:"cwe,omitempty"`
	References          []string    `json:"references,omitempty"`
	Timestamp           time.Time   `json:"timestamp"`
	RawRequest          string      `json:"raw_request,omitempty"`
	RawResponse         string      `json:"raw_response,omitempty"`
	ExecutionVerified   bool        `json:"execution_verified,omitempty"`
	ExecutionConfidence float64     `json:"execution_confidence,omitempty"`
	ScreenshotPath      string      `json:"screenshot_path,omitempty"`
	CSPBypasses         []CSPBypass `json:"csp_bypasses,omitempty"`
}
