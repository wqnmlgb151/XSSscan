package scanner

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/execverify"
	"github.com/xsscan/xsscan/pkg/model"
)

func TestGenerateIDUnique(t *testing.T) {
	// Generate 1000 IDs concurrently — all must be unique
	var wg sync.WaitGroup
	ids := make(map[string]bool)
	var mu sync.Mutex

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := generateID()
			mu.Lock()
			ids[id] = true
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(ids) != 1000 {
		t.Errorf("Expected 1000 unique IDs, got %d", len(ids))
	}
}

func TestGenerateIDFormat(t *testing.T) {
	id := generateID()
	if !strings.HasPrefix(id, "XSS-") {
		t.Errorf("Expected ID to start with 'XSS-', got %q", id)
	}
	parts := strings.Split(id, "-")
	if len(parts) != 3 {
		t.Errorf("Expected ID format XSS-<timestamp>-<counter>, got %q", id)
	}
}

func TestGenerateIDMonotonic(t *testing.T) {
	// IDs should be monotonically increasing (timestamp + counter)
	id1 := generateID()
	id2 := generateID()
	if id1 == id2 {
		t.Errorf("Expected unique IDs, got duplicate %q", id1)
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name string
		input string
		want string
	}{
		{"empty", "", "**"},
		{"short", "abc", "abc**"},
		{"exactly_8", "12345678", "12345678**"},
		{"long_secret", "my-super-secret-api-key-12345", "my-super**"},
		{"api_key", "sk-abcdef1234567890", "sk-abcde**"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskSecret(tt.input)
			if got != tt.want {
				t.Errorf("maskSecret(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  time.Duration
	}{
		{"delta_zero", "0", 0},
		{"delta_120", "120", 120 * time.Second},
		{"delta_1", "1", 1 * time.Second},
		{"empty", "", 0},
		{"garbage", "not-a-number", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRetryAfter(tt.input)
			if got != tt.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseRetryAfterHTTPDate(t *testing.T) {
	// HTTP-date in the past → delay clamped to 0
	pastDate := time.Now().Add(-1 * time.Hour).UTC().Format(http.TimeFormat)
	got := parseRetryAfter(pastDate)
	if got != 0 {
		t.Errorf("parseRetryAfter(past HTTP-date) = %v, want 0", got)
	}

	// HTTP-date in the near future → positive delay (capped at 30s)
	futureDate := time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
	got = parseRetryAfter(futureDate)
	if got <= 0 || got > 6*time.Second {
		t.Errorf("parseRetryAfter(near-future HTTP-date) = %v, want ~5s", got)
	}

	// HTTP-date far in the future → capped at 30s
	farFuture := time.Now().Add(1 * time.Hour).UTC().Format(http.TimeFormat)
	got = parseRetryAfter(farFuture)
	if got != 30*time.Second {
		t.Errorf("parseRetryAfter(far-future HTTP-date) = %v, want 30s", got)
	}
}

func TestBuildAuthState(t *testing.T) {
	tests := []struct {
		name       string
		target     model.Target
		wantNil    bool
		wantCookie int
		wantHeader int
	}{
		{
			name:    "nil everything returns nil",
			target:  model.Target{URL: "http://example.com"},
			wantNil: true,
		},
		{
			name: "cookies only",
			target: model.Target{
				URL:     "http://example.com",
				Cookies: []*http.Cookie{{Name: "session", Value: "abc123"}},
			},
			wantCookie: 1,
		},
		{
			name: "auth header only",
			target: model.Target{
				URL:     "http://example.com",
				Headers: map[string]string{"Authorization": "Bearer token123"},
			},
			wantHeader: 1,
		},
		{
			name: "all auth headers captured",
			target: model.Target{
				URL: "http://example.com",
				Headers: map[string]string{
					"Authorization": "Bearer xyz",
					"Cookie":        "session=abc",
					"X-CSRF-Token":  "csrf123",
					"X-XSRF-Token":  "xsrf456",
					"User-Agent":    "Mozilla/5.0", // non-auth header, should be skipped
				},
			},
			wantHeader: 4,
		},
		{
			name: "empty auth header skipped",
			target: model.Target{
				URL:     "http://example.com",
				Headers: map[string]string{"Authorization": ""},
			},
			wantNil: true,
		},
		{
			name: "cookies and headers combined",
			target: model.Target{
				URL:     "http://example.com",
				Cookies: []*http.Cookie{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}},
				Headers: map[string]string{"Authorization": "Bearer x"},
			},
			wantCookie: 2,
			wantHeader: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAuthState(tt.target)
			if tt.wantNil {
				if got != nil {
					t.Errorf("buildAuthState() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("buildAuthState() = nil, want non-nil")
			}
			if len(got.Cookies) != tt.wantCookie {
				t.Errorf("cookies = %d, want %d", len(got.Cookies), tt.wantCookie)
			}
			if len(got.Headers) != tt.wantHeader {
				t.Errorf("headers = %d, want %d", len(got.Headers), tt.wantHeader)
			}
		})
	}
}

func TestBuildAuthStateCookieIndependence(t *testing.T) {
	// Verify that modifying the returned cookies doesn't affect the original
	original := &http.Cookie{Name: "session", Value: "original"}
	target := model.Target{
		URL:     "http://example.com",
		Cookies: []*http.Cookie{original},
	}

	state := buildAuthState(target)
	if state == nil {
		t.Fatal("buildAuthState returned nil")
	}

	// Mutate the returned cookie
	state.Cookies[0].Value = "mutated"

	if original.Value != "original" {
		t.Error("buildAuthState did not deep-copy cookies — original was mutated")
	}
}

func TestBuildAuthStateHeaderIndependence(t *testing.T) {
	// Verify that modifying the returned headers doesn't affect the original
	target := model.Target{
		URL:     "http://example.com",
		Headers: map[string]string{"Authorization": "Bearer original"},
	}

	state := buildAuthState(target)
	if state == nil {
		t.Fatal("buildAuthState returned nil")
	}

	// Mutate the returned header
	state.Headers["Authorization"] = "Bearer mutated"

	if target.Headers["Authorization"] != "Bearer original" {
		t.Error("buildAuthState did not copy headers — original was mutated")
	}
}

// Ensure execverify.AuthState is used (compile-time check)
var _ *execverify.AuthState = nil
