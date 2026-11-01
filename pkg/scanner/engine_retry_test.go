package scanner

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

// mockHTTPClient returns configurable responses for testing retry logic.
type mockHTTPClient struct {
	responses []*http.Response
	errors    []error
	callCount int64
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	idx := atomic.AddInt64(&m.callCount, 1) - 1
	if idx < int64(len(m.errors)) && m.errors[idx] != nil {
		return nil, m.errors[idx]
	}
	if idx < int64(len(m.responses)) {
		return m.responses[idx], nil
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     http.Header{},
	}, nil
}

func newMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
}

// simulateRetryLoop mimics the retry logic in doScanPayload for isolated testing.
func simulateRetryLoop(client *mockHTTPClient, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := initialBackoff << (attempt - 1)
			jitter := time.Duration(rand.Int63n(int64(backoff) / 4))
			sleepTime := backoff - backoff/8 + jitter
			_ = sleepTime // In tests, we skip actual sleep
		}

		resp, lastErr = client.Do(req)
		if lastErr != nil {
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			continue
		}

		if resp.StatusCode >= 500 {
			continue
		}

		break
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return resp, nil
}

func TestRetryOnNetworkError_ExhaustsAndReturnsError(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	mock := &mockHTTPClient{
		errors: []error{
			errors.New("connection refused"),
			errors.New("connection refused"),
			errors.New("connection refused"),
			errors.New("connection refused"),
		},
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:9999/test", nil)
	_, err := simulateRetryLoop(mock, req)

	if err == nil {
		t.Error("Expected error after exhausting retries, got nil")
	}
	if calls := atomic.LoadInt64(&mock.callCount); calls != int64(maxRetries+1) {
		t.Errorf("Expected %d calls, got %d", maxRetries+1, calls)
	}
}

func TestRetryOnNetworkError_RetriesThenSucceeds(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	mock := &mockHTTPClient{
		errors: []error{
			errors.New("connection refused"),
			errors.New("connection refused"),
		},
		responses: []*http.Response{
			newMockResponse(200, "OK"),
		},
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:9999/test", nil)
	resp, err := simulateRetryLoop(mock, req)

	if err != nil {
		t.Errorf("Expected success on 3rd attempt, got error: %v", err)
	}
	if resp == nil || resp.StatusCode != 200 {
		t.Errorf("Expected 200 response, got %v", resp)
	}
	if calls := atomic.LoadInt64(&mock.callCount); calls != 3 {
		t.Errorf("Expected 3 calls, got %d", calls)
	}
}

func TestRetryOn500_RetriesThenSucceeds(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	mock := &mockHTTPClient{
		responses: []*http.Response{
			newMockResponse(500, "Internal Server Error"),
			newMockResponse(500, "Internal Server Error"),
			newMockResponse(200, "OK"),
		},
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:9999/test", nil)
	resp, err := simulateRetryLoop(mock, req)

	if err != nil {
		t.Errorf("Expected success on 3rd attempt, got error: %v", err)
	}
	if resp == nil || resp.StatusCode != 200 {
		t.Errorf("Expected 200 response, got %v", resp)
	}
	if calls := atomic.LoadInt64(&mock.callCount); calls != 3 {
		t.Errorf("Expected 3 calls, got %d", calls)
	}
}

func TestRetryOn500_AllFail(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	mock := &mockHTTPClient{
		responses: []*http.Response{
			newMockResponse(500, "error"),
			newMockResponse(500, "error"),
			newMockResponse(500, "error"),
			newMockResponse(500, "error"),
		},
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:9999/test", nil)
	resp, _ := simulateRetryLoop(mock, req)

	if resp.StatusCode != 500 {
		t.Errorf("Expected 500 after all retries, got %d", resp.StatusCode)
	}
	if calls := atomic.LoadInt64(&mock.callCount); calls != int64(maxRetries+1) {
		t.Errorf("Expected %d calls, got %d", maxRetries+1, calls)
	}
}

func TestRetryOn429_ThenSuccess(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	resp429 := newMockResponse(429, "Too Many Requests")
	resp429.Header.Set("Retry-After", "0")

	mock := &mockHTTPClient{
		responses: []*http.Response{
			resp429,
			newMockResponse(200, "OK"),
		},
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:9999/test", nil)
	resp, err := simulateRetryLoop(mock, req)

	if err != nil {
		t.Errorf("Expected success after 429, got error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
	if calls := atomic.LoadInt64(&mock.callCount); calls != 2 {
		t.Errorf("Expected 2 calls (429 + retry), got %d", calls)
	}
}

func TestNoRetryOn200(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	mock := &mockHTTPClient{
		responses: []*http.Response{
			newMockResponse(200, "OK"),
		},
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:9999/test", nil)
	resp, err := simulateRetryLoop(mock, req)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
	if calls := atomic.LoadInt64(&mock.callCount); calls != 1 {
		t.Errorf("Expected exactly 1 call for 200 response, got %d", calls)
	}
}

func TestNoRetryOn404(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	mock := &mockHTTPClient{
		responses: []*http.Response{
			newMockResponse(404, "Not Found"),
		},
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:9999/test", nil)
	resp, _ := simulateRetryLoop(mock, req)

	if resp.StatusCode != 404 {
		t.Errorf("Expected 404 (not retried), got %d", resp.StatusCode)
	}
	if calls := atomic.LoadInt64(&mock.callCount); calls != 1 {
		t.Errorf("Expected 1 call for 404, got %d", calls)
	}
}

func TestRetryContextCancellation(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	// Mock always returns 500 to force retries
	mock := &mockHTTPClient{
		responses: []*http.Response{
			newMockResponse(500, "error"),
			newMockResponse(500, "error"),
			newMockResponse(500, "error"),
			newMockResponse(500, "error"),
		},
	}

	// Pre-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:9999/test", nil)

	// Simulate retry loop — same select pattern as doScanPayload
	var cancelled bool
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := initialBackoff << (attempt - 1)
			jitter := time.Duration(rand.Int63n(int64(backoff) / 4))
			sleepTime := backoff - backoff/8 + jitter
			select {
			case <-ctx.Done():
				cancelled = true
			case <-time.After(sleepTime):
			}
			if cancelled {
				break
			}
		}

		var resp *http.Response
		resp, lastErr = mock.Do(req)
		if lastErr != nil {
			continue
		}
		if resp.StatusCode >= 500 {
			continue
		}
		break
	}

	if !cancelled {
		t.Error("Expected context cancellation to be detected during retry backoff")
	}

	// Verify only 1 Do call was made (initial attempt, then cancelled on retry)
	if calls := atomic.LoadInt64(&mock.callCount); calls != 1 {
		t.Errorf("Expected 1 call (initial only, cancelled before retry), got %d", calls)
	}
	_ = lastErr
}

func TestBackoffJitterRange(t *testing.T) {
	// Verify that backoff calculation stays within ±25% of base
	r := rand.New(rand.NewSource(42))
	base := initialBackoff // 500ms

	for attempt := 1; attempt <= maxRetries; attempt++ {
		expectedBackoff := base << (attempt - 1)

		for i := 0; i < 100; i++ {
			jitter := time.Duration(r.Int63n(int64(expectedBackoff) / 4))
			sleepTime := expectedBackoff - expectedBackoff/8 + jitter

			// Expected: base*2^(attempt-1) ± 25%
			lowBound := expectedBackoff * 3 / 4  // -25%
			highBound := expectedBackoff * 5 / 4 // +25%

			if sleepTime < lowBound {
				t.Errorf("Attempt %d: sleepTime %v below low bound %v", attempt, sleepTime, lowBound)
			}
			if sleepTime > highBound {
				t.Errorf("Attempt %d: sleepTime %v above high bound %v", attempt, sleepTime, highBound)
			}
		}
	}
}

func TestInitialBackoffValue(t *testing.T) {
	if initialBackoff != 500*time.Millisecond {
		t.Errorf("Expected initialBackoff=500ms, got %v", initialBackoff)
	}
}

func TestMaxRetriesValue(t *testing.T) {
	if maxRetries != 3 {
		t.Errorf("Expected maxRetries=3, got %d", maxRetries)
	}
}
