package httpclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
)

func TestCapturedSummaryMatchesRequestWithoutChangingEvidence(t *testing.T) {
	c := &Capture{requestHead: "POST / HTTP/1.1\r\nAuthorization: Bearer actual\r\n\r\n", requestBody: []byte{'x', 0, 255}, responseHead: "HTTP/1.1 200 OK\r\n\r\n", responseBody: bytes.Repeat([]byte{0, 255}, MaxEvidenceBody/2)}
	c.exchange.RequestTruncated = true
	req, _ := http.NewRequestWithContext(context.WithValue(context.Background(), recordKey{}, c), "POST", "http://127.0.0.1", nil)
	resp := &http.Response{Request: req}
	before := Captured(resp)
	summary := CapturedSummary(resp)
	sum := sha256.Sum256([]byte(before.Request))
	if summary.RequestDigest != hex.EncodeToString(sum[:]) || !summary.RequestTruncated || !summary.ResponseIncomplete {
		t.Fatal(summary)
	}
	after := Captured(resp)
	if before.Request != after.Request || before.ResponseBase64 != after.ResponseBase64 || string(c.responseBody) != string(bytes.Repeat([]byte{0, 255}, MaxEvidenceBody/2)) {
		t.Fatal("summary mutated evidence")
	}
	if CapturedSummary(nil) != (CaptureSummary{}) {
		t.Fatal("nil capture")
	}
}

func BenchmarkCaptureSummaryLargeResponse(b *testing.B) {
	c := &Capture{requestHead: "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", responseHead: "HTTP/1.1 200 OK\r\n\r\n", responseBody: bytes.Repeat([]byte("x"), MaxEvidenceBody), complete: true}
	req, _ := http.NewRequestWithContext(context.WithValue(context.Background(), recordKey{}, c), "GET", "http://127.0.0.1", nil)
	resp := &http.Response{Request: req}
	b.Run("full_snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = Captured(resp)
		}
	})
	b.Run("summary", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = CapturedSummary(resp)
		}
	})
}
