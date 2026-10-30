package model

// ModuleResult records coverage independently of vulnerability findings.
type ModuleResult struct {
	Coverage   []CheckCoverage `json:"coverage,omitempty"`
	Type       string          `json:"type"`
	Target     string          `json:"target"`
	Status     ScanStatus      `json:"status"`
	Reason     string          `json:"reason,omitempty"`
	Issues     []ScanIssue     `json:"issues,omitempty"`
	Requests   int             `json:"requests"`
	Candidates int             `json:"candidates"`
	Findings   int             `json:"findings"`
	Duration   int64           `json:"duration_ms"`
}
