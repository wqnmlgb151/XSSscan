package verify

import (
	"net/http"
	"strings"

	"github.com/xsscan/xsscan/pkg/internal/text"
	"github.com/xsscan/xsscan/pkg/payload"
)

// WAFResult contains WAF detection results
type WAFResult struct {
	Detected bool
	Name     string
	Evidence string
}

// wafSignature defines detection patterns and bypass strategies for known WAFs.
// BypassStrategies lists mutation types (from pkg/payload) that are empirically
// effective against this WAF. The scanner uses these to prioritize mutations
// instead of trying all variants blindly.
//
// NOTE: pkg/payload/mutator.go has a parallel getWAFStrategies() mapping.
// The two must be kept in sync — import cycle prevents sharing.
type wafSignature struct {
	Name             string
	Headers          []string
	BodyPatterns     []string
	StatusCodes      []int
	BypassStrategies []payload.MutationType
}

var wafSignatures = []wafSignature{
	{
		Name:             "Cloudflare",
		Headers:          []string{"cf-ray", "__cfduid", "cf-cache-status", "cf-request-id"},
		BodyPatterns:     []string{"attention required", "cloudflare", "cf-browser-verification", "checking your browser"},
		StatusCodes:      []int{403, 503, 522, 524},
		BypassStrategies: []payload.MutationType{payload.MutationCaseMix, payload.MutationCommentInjection, payload.MutationAltFunction, payload.MutationTabInjection, payload.MutationBreakoutTextarea},
	},
	{
		Name:             "AWS WAF",
		Headers:          []string{"x-amzn-requestid", "x-amz-cf-id", "x-amzn-waf-action"},
		BodyPatterns:     []string{"request blocked", "aws waf", "bad request"},
		StatusCodes:      []int{403},
		BypassStrategies: []payload.MutationType{payload.MutationBreakoutTextarea, payload.MutationAltFunction, payload.MutationEntityPlusCase, payload.MutationNewlineInjection, payload.MutationBacktickFn},
	},
	{
		Name:             "Akamai",
		Headers:          []string{"akamai-grn", "x-akamai-transformed", "akamai-origin-hop"},
		BodyPatterns:     []string{"reference #", "akamai", "access denied"},
		StatusCodes:      []int{403, 405},
		BypassStrategies: []payload.MutationType{payload.MutationTabInjection, payload.MutationNewlineInjection, payload.MutationCommentInjection, payload.MutationCaseMix, payload.MutationSpaceToSlash},
	},
	{
		Name:             "ModSecurity",
		Headers:          []string{"mod_security", "modsecurity"},
		BodyPatterns:     []string{"not acceptable!", "modsecurity action", "406 not acceptable"},
		StatusCodes:      []int{403, 406, 501},
		BypassStrategies: []payload.MutationType{payload.MutationNewlineInjection, payload.MutationTabInjection, payload.MutationSpaceToSlash, payload.MutationEntityAngleBrackets, payload.MutationStringConcat},
	},
	{
		Name:             "F5 BIG-IP",
		Headers:          []string{"x-cnection", "x-info", "bigip"},
		BodyPatterns:     []string{"the requested url was rejected", "bigip", "support id"},
		StatusCodes:      []int{403},
		BypassStrategies: []payload.MutationType{payload.MutationCaseMix, payload.MutationCommentInjection, payload.MutationTabInjection, payload.MutationAltFunction, payload.MutationEntityAngleBrackets},
	},
	{
		Name:             "Imperva",
		Headers:          []string{"x-iinfo", "x-cdn", "incapsula"},
		BodyPatterns:     []string{"incapsula", "imperva", "request unsuccessful"},
		StatusCodes:      []int{403},
		BypassStrategies: []payload.MutationType{payload.MutationEntityPlusCase, payload.MutationBreakoutTextarea, payload.MutationCommentInjection, payload.MutationNewlineInjection, payload.MutationBacktickFn},
	},
	{
		Name:             "Sucuri",
		Headers:          []string{"x-sucuri-id", "x-sucuri-cache", "sucuri"},
		BodyPatterns:     []string{"sucuri", "access denied", "blocked"},
		StatusCodes:      []int{403},
		BypassStrategies: []payload.MutationType{payload.MutationCaseMix, payload.MutationSpaceToSlash, payload.MutationTabInjection, payload.MutationAltFunction, payload.MutationEntityAngleBrackets},
	},
	{
		Name:             "Wordfence",
		Headers:          []string{"wordfence"},
		BodyPatterns:     []string{"wordfence", "your access to this site has been limited"},
		StatusCodes:      []int{403, 503},
		BypassStrategies: []payload.MutationType{payload.MutationEntityAngleBrackets, payload.MutationEntityPlusCase, payload.MutationBreakoutTextarea, payload.MutationCommentInjection, payload.MutationStringConcat},
	},
}

// GetWAFStrategies returns the recommended bypass strategy names for a detected WAF.
// Returns nil if the WAF is unknown or has no strategies defined.
func GetWAFStrategies(wafName string) []payload.MutationType {
	for _, sig := range wafSignatures {
		if sig.Name == wafName {
			return sig.BypassStrategies
		}
	}
	return nil
}

// DetectWAF checks if a response shows signs of WAF interception.
func DetectWAF(resp *http.Response, body string) WAFResult {
	bodyLower := strings.ToLower(body)

	for _, sig := range wafSignatures {
		// Check response header names only — matching values causes false positives
		// when header values happen to contain WAF-like substrings (e.g., UUIDs).
		for _, headerPattern := range sig.Headers {
			for key := range resp.Header {
				if text.ContainsCI(key, headerPattern) {
					return WAFResult{true, sig.Name, "header: " + key}
				}
			}
		}

		// Check body patterns (using pre-lowercased body)
		for _, pattern := range sig.BodyPatterns {
			if strings.Contains(bodyLower, strings.ToLower(pattern)) {
				return WAFResult{true, sig.Name, "body: " + pattern}
			}
		}

		// Check status codes only when corroborated by body pattern match
		if len(body) < 5000 {
			for _, code := range sig.StatusCodes {
				if resp.StatusCode == code {
					for _, pattern := range sig.BodyPatterns {
						if strings.Contains(bodyLower, strings.ToLower(pattern)) {
							return WAFResult{true, sig.Name, "status+body: " + pattern}
						}
					}
				}
			}
		}
	}

	return WAFResult{Detected: false}
}

