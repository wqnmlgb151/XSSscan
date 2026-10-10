package model

// ScanStatus describes completion, independently of whether findings exist.
type ScanStatus string

const (
	ScanCompleted ScanStatus = "completed"
	ScanPartial   ScanStatus = "partial"
	ScanFailed    ScanStatus = "failed"
	ScanCanceled  ScanStatus = "canceled"
	ScanSkipped   ScanStatus = "skipped"
)

// ScanIssue retains the target and stage of an incomplete check.
type ScanIssue struct {
	HTTP    *HTTPExchange `json:"http,omitempty"`
	Target  string        `json:"target"`
	Stage   string        `json:"stage"`
	Message string        `json:"message"`
}

// MergeStatus combines independent checks without letting success erase failure.
func MergeStatus(a, b ScanStatus) ScanStatus {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if a == ScanCanceled || b == ScanCanceled {
		return ScanCanceled
	}
	if a == b {
		return a
	}
	return ScanPartial
}
