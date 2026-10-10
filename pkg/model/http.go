package model

import "unicode/utf8"

// NeedsBinaryEvidence includes XML 1.0 controls as well as invalid UTF-8.
// Base64 preserves the original bytes where text reports cannot represent them.
func NeedsBinaryEvidence(raw string) bool {
	if !utf8.ValidString(raw) {
		return true
	}
	for _, r := range raw {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
			return true
		}
	}
	return false
}

// HTTPExchange is a logical HTTP replay snapshot, not encrypted wire frames.
// Body prefixes are bounded; truncation and incomplete reads remain explicit.
type HTTPExchange struct {
	InitialURL string `json:"initial_url,omitempty"`
	InitialRequest string `json:"initial_request,omitempty"`
	InitialRequestBase64 string `json:"initial_request_base64,omitempty"`
	InitialRequestTruncated bool `json:"initial_request_truncated,omitempty"`
	RequestBase64      string `json:"request_base64,omitempty"`
	ResponseBase64     string `json:"response_base64,omitempty"`
	URL                string `json:"url"`
	Request            string `json:"request"`
	Response           string `json:"response"`
	RequestTruncated   bool   `json:"request_truncated,omitempty"`
	ResponseTruncated  bool   `json:"response_truncated,omitempty"`
	ResponseIncomplete bool   `json:"response_incomplete,omitempty"`
}
