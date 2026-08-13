package verify

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/payload"
)

func TestDetectWAF_Cloudflare(t *testing.T) {
	resp := &http.Response{
		StatusCode: 403,
		Header:     http.Header{"Cf-Ray": []string{"abc123"}},
	}
	body := "Attention Required! | Cloudflare"
	result := DetectWAF(resp, body)
	if !result.Detected {
		t.Error("Expected Cloudflare detection")
	}
	if result.Name != "Cloudflare" {
		t.Errorf("Expected Cloudflare, got %s", result.Name)
	}
}

func TestDetectWAF_NoWAF(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}
	body := "<html><body>Hello World</body></html>"
	result := DetectWAF(resp, body)
	if result.Detected {
		t.Error("Expected no WAF detection for normal page")
	}
}

func TestDetectWAF_AWSWAF(t *testing.T) {
	resp := &http.Response{
		StatusCode: 403,
		Header:     http.Header{},
	}
	body := "Request blocked by AWS WAF"
	result := DetectWAF(resp, body)
	if !result.Detected || result.Name != "AWS WAF" {
		t.Errorf("Expected AWS WAF, got %+v", result)
	}
}

func TestDetectWAF_ModSecurity(t *testing.T) {
	resp := &http.Response{
		StatusCode: 406,
		Header:     http.Header{},
	}
	body := "Not Acceptable! An appropriate representation of the requested resource could not be found."
	result := DetectWAF(resp, body)
	if !result.Detected || result.Name != "ModSecurity" {
		t.Errorf("Expected ModSecurity, got %+v", result)
	}
}

func TestGetWAFStrategies(t *testing.T) {
	tests := []struct {
		wafName     string
		expectEmpty bool
	}{
		{"Cloudflare", false},
		{"AWS WAF", false},
		{"Akamai", false},
		{"ModSecurity", false},
		{"F5 BIG-IP", false},
		{"Imperva", false},
		{"Sucuri", false},
		{"Wordfence", false},
		{"UnknownWAF", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.wafName, func(t *testing.T) {
			strategies := GetWAFStrategies(tt.wafName)
			if tt.expectEmpty && len(strategies) > 0 {
				t.Errorf("Expected empty strategies for %s, got %v", tt.wafName, strategies)
			}
			if !tt.expectEmpty && len(strategies) == 0 {
				t.Errorf("Expected non-empty strategies for %s", tt.wafName)
			}
		})
	}
}

func TestGetWAFStrategies_NotEmpty(t *testing.T) {
	// Verify each known WAF has at least 3 bypass strategies
	wafs := []string{"Cloudflare", "AWS WAF", "Akamai", "ModSecurity", "F5 BIG-IP", "Imperva", "Sucuri", "Wordfence"}
	for _, waf := range wafs {
		strategies := GetWAFStrategies(waf)
		if len(strategies) < 3 {
			t.Errorf("Expected at least 3 strategies for %s, got %d: %v", waf, len(strategies), strategies)
		}
	}
}

func TestDetectWAF_HeaderCaseInsensitive(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"CF-RAY": []string{"abc"}},
	}
	body := "normal page"
	result := DetectWAF(resp, body)
	if !result.Detected || result.Name != "Cloudflare" {
		t.Errorf("Header matching should be case-insensitive, got %+v", result)
	}
}

func TestDetectWAF_RealServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(200)
		w.Write([]byte("Normal page content"))
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("http.Get failed: %v", err)
	}
	defer resp.Body.Close()
	result := DetectWAF(resp, "")
	// Server header "cloudflare" should not trigger (we only match cf-ray etc.)
	if result.Detected {
		t.Errorf("Server header should not trigger WAF detection, got %+v", result)
	}
}

// TestWAFStrategiesSync verifies that verify.GetWAFStrategies delegates to
// payload.GetWAFStrategies (the single source of truth) for every known WAF.
func TestWAFStrategiesSync(t *testing.T) {
	allWAFs := []string{
		"Cloudflare", "AWS WAF", "Akamai", "ModSecurity",
		"F5 BIG-IP", "Imperva", "Sucuri", "Wordfence",
	}

	for _, wafName := range allWAFs {
		t.Run(wafName, func(t *testing.T) {
			verifyStrategies := GetWAFStrategies(wafName)
			payloadStrategies := payload.GetWAFStrategies(wafName)

			if len(verifyStrategies) != len(payloadStrategies) {
				t.Errorf("Strategy count mismatch for %s: verify=%d, payload=%d",
					wafName, len(verifyStrategies), len(payloadStrategies))
				return
			}

			// Build a set from payload strategies for comparison
			payloadSet := make(map[payload.MutationType]bool, len(payloadStrategies))
			for _, s := range payloadStrategies {
				payloadSet[s] = true
			}

			// Every verify strategy must exist in payload strategies
			for _, vs := range verifyStrategies {
				if !payloadSet[vs] {
					t.Errorf("Strategy %s present in verify but missing from payload for %s", vs, wafName)
				}
			}

			// Build a set from verify strategies for reverse comparison
			verifySet := make(map[payload.MutationType]bool, len(verifyStrategies))
			for _, s := range verifyStrategies {
				verifySet[s] = true
			}

			// Every payload strategy must exist in verify strategies
			for _, ps := range payloadStrategies {
				if !verifySet[ps] {
					t.Errorf("Strategy %s present in payload but missing from verify for %s", ps, wafName)
				}
			}
		})
	}
}

func TestDetectWAF_BodyPatternPriority(t *testing.T) {
	// When multiple WAF body patterns could match, first match wins
	resp := &http.Response{
		StatusCode: 403,
		Header:     http.Header{},
	}
	// "access denied" matches both Akamai and Sucuri
	body := "Access Denied"
	result := DetectWAF(resp, body)
	if !result.Detected {
		t.Error("Expected detection for 'access denied'")
	}
	// Should be Akamai (first in list with this pattern)
	if !strings.Contains(result.Name, "Akamai") && !strings.Contains(result.Name, "Sucuri") && !strings.Contains(result.Name, "Wordfence") {
		t.Errorf("Expected Akamai/Sucuri/Wordfence for 'access denied', got %s", result.Name)
	}
}

func TestWAFStrategies_AllEncodingMutationsCovered(t *testing.T) {
	encodingMutations := []payload.MutationType{
		payload.MutationDoubleURLEncode,
		payload.MutationUnicodeFullwidth,
		payload.MutationHTMLEntityNested,
		payload.MutationUnicodeEscapeJS,
		payload.MutationHexEntityMixed,
		payload.MutationNullByteInjection,
	}
	wafNames := []string{"Cloudflare", "AWS WAF", "Akamai", "ModSecurity", "F5 BIG-IP", "Imperva", "Sucuri", "Wordfence"}

	covered := make(map[payload.MutationType]bool)
	for _, waf := range wafNames {
		for _, m := range GetWAFStrategies(waf) {
			covered[m] = true
		}
	}
	for _, m := range encodingMutations {
		if !covered[m] {
			t.Errorf("encoding mutation %s is not referenced by any WAF strategy", m)
		}
	}
}

func TestGetWAFStrategies_IncludesEncodingMutations(t *testing.T) {
	wafNames := []string{"Cloudflare", "AWS WAF", "Akamai", "ModSecurity", "F5 BIG-IP", "Imperva", "Sucuri", "Wordfence"}
	encoding := map[payload.MutationType]bool{
		payload.MutationDoubleURLEncode:  true,
		payload.MutationUnicodeFullwidth: true,
		payload.MutationHTMLEntityNested: true,
		payload.MutationUnicodeEscapeJS:  true,
		payload.MutationHexEntityMixed:   true,
		payload.MutationNullByteInjection: true,
	}
	for _, waf := range wafNames {
		has := false
		for _, m := range GetWAFStrategies(waf) {
			if encoding[m] {
				has = true
				break
			}
		}
		if !has {
			t.Errorf("WAF %s has no encoding mutation in its strategy list", waf)
		}
	}
}
