package model

import "fmt"

// CheckCoverage counts logical checks within one named stage, not HTTP traffic.
// Stages with unknown plans must not be interpreted as zero-work full coverage.
type CheckCoverage struct {
	Stage        string `json:"stage"`
	Target       string `json:"target,omitempty"`
	PlannedKnown bool   `json:"planned_known"`
	Planned      int    `json:"planned"`
	Started      int    `json:"started"`
	Completed    int    `json:"completed"`
	Failed       int    `json:"failed"`
	Canceled     int    `json:"canceled"`
	NotStarted   int    `json:"not_started"`
}

func (c CheckCoverage) String() string {
	plan := "unknown"
	if c.PlannedKnown {
		plan = fmt.Sprint(c.Planned)
	}
	stage := c.Stage
	if c.Target != "" {
		stage += " (" + c.Target + ")"
	}
	return fmt.Sprintf("%s: planned=%s started=%d completed=%d failed=%d canceled=%d not_started=%d", stage, plan, c.Started, c.Completed, c.Failed, c.Canceled, c.NotStarted)
}
