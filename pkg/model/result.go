package model

// ScanResult contains all findings from a scan
type ScanResult struct {
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
	Stats    ScanStats `json:"stats"`
}

// WAFInfo describes a detected web application firewall.
// Presence of *WAFInfo in ScanStats indicates detection; nil means no WAF.
type WAFInfo struct {
	Name     string `json:"name"`
	Bypassed bool   `json:"bypassed"`
}

// ScanStats contains scan statistics
type ScanStats struct {
	Coverage        []CheckCoverage `json:"coverage,omitempty"`
	Modules         []ModuleResult  `json:"modules,omitempty"`
	Status          ScanStatus      `json:"status,omitempty"`
	Issues          []ScanIssue     `json:"issues,omitempty"`
	RequestsSent    int             `json:"requests_sent,omitempty"`
	StartTime       int64           `json:"start_time"`
	EndTime         int64           `json:"end_time"`
	Duration        int64           `json:"duration_ms"`
	ParametersFound int             `json:"parameters_found"`
	PayloadsSent    int             `json:"payloads_sent"`
	ProbeFiltered   int             `json:"probe_filtered,omitempty"`
	Errors          int             `json:"errors,omitempty"`
	WAF             *WAFInfo        `json:"waf,omitempty"`
	// CrossModule carries leads one module produced that another could act on. It never
	// carries a verdict: see CrossModuleSummary for why that is structural.
	CrossModule CrossModuleSummary `json:"cross_module,omitempty"`
}
