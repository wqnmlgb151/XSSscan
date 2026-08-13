package verify

import (
	"net/http"
	"strings"

	"github.com/xsscan/xsscan/pkg/payload"
)

// WAFResult contains WAF detection results
type WAFResult struct {
	Detected bool
	Name     string
	Evidence string
}

// wafSignature defines detection patterns for known WAFs.
// Detection is header-name + body-pattern based; status codes alone are too
// noisy (a bare 403 is not evidence of any specific WAF).
// Bypass strategy lists live in payload.GetWAFStrategies (single source of truth).
type wafSignature struct {
	Name              string
	Headers           []string
	BodyPatterns      []string
	BodyPatternsLower []string // pre-lowercased at init
}

var wafSignatures = []wafSignature{
	{
		Name:         "Cloudflare",
		Headers:      []string{"cf-ray", "__cfduid", "cf-cache-status", "cf-request-id"},
		BodyPatterns: []string{"attention required", "cloudflare", "cf-browser-verification", "checking your browser"},
	},
	{
		Name:         "AWS WAF",
		Headers:      []string{"x-amzn-requestid", "x-amz-cf-id", "x-amzn-waf-action"},
		BodyPatterns: []string{"request blocked", "aws waf", "bad request"},
	},
	{
		Name:         "Akamai",
		Headers:      []string{"akamai-grn", "x-akamai-transformed", "akamai-origin-hop"},
		BodyPatterns: []string{"reference #", "akamai", "access denied"},
	},
	{
		Name:         "ModSecurity",
		Headers:      []string{"mod_security", "modsecurity"},
		BodyPatterns: []string{"not acceptable!", "modsecurity action", "406 not acceptable"},
	},
	{
		Name:         "F5 BIG-IP",
		Headers:      []string{"x-cnection", "x-info", "bigip"},
		BodyPatterns: []string{"the requested url was rejected", "bigip", "support id"},
	},
	{
		Name:         "Imperva",
		Headers:      []string{"x-iinfo", "x-cdn", "incapsula"},
		BodyPatterns: []string{"incapsula", "imperva", "request unsuccessful"},
	},
	{
		Name:         "Sucuri",
		Headers:      []string{"x-sucuri-id", "x-sucuri-cache", "sucuri"},
		BodyPatterns: []string{"sucuri", "access denied", "blocked"},
	},
	{
		Name:         "Wordfence",
		Headers:      []string{"wordfence"},
		BodyPatterns: []string{"wordfence", "your access to this site has been limited"},
	},
	{
		Name:         "Aliyun WAF",
		Headers:      []string{"x-waf-error", "x-waf-status", "aliyun-waf", "x-aliyun-waf"},
		BodyPatterns: []string{"aliyun waf", "blocked by alibaba cloud", "waf intercept"},
	},
	{
		Name:         "Tencent WAF",
		Headers:      []string{"x-waf-uuid", "tx-waf", "waf-request-id"},
		BodyPatterns: []string{"tencent cloud waf", "waf.tencent", "访问被拒绝"},
	},
	{
		Name:         "Safedog",
		Headers:      []string{"safedog", "x-safe-dog"},
		BodyPatterns: []string{"safedog", "waf/2.0"},
	},
	{
		Name:         "BaoTa WAF",
		Headers:      []string{"btwaf"},
		BodyPatterns: []string{"btwaf", "宝塔", "您的请求带有不合法参数"},
	},
}

// GetWAFStrategies returns the recommended bypass strategy names for a detected WAF.
// Delegates to payload.GetWAFStrategies — the single source of truth.
func GetWAFStrategies(wafName string) []payload.MutationType {
	return payload.GetWAFStrategies(wafName)
}

// DetectWAF checks if a response shows signs of WAF interception.
// Callers that already have a lowercased body should use DetectWAFWithLower
// to avoid a redundant full-body lowercase copy.
func DetectWAF(resp *http.Response, body string) WAFResult {
	return DetectWAFWithLower(resp, strings.ToLower(body))
}

// DetectWAFWithLower checks for WAF interception using a pre-lowercased body.
// bodyLower must be strings.ToLower(body).
func DetectWAFWithLower(resp *http.Response, bodyLower string) WAFResult {
	for _, sig := range wafSignatures {
		// Check response header names only — matching values causes false positives
		// when header values happen to contain WAF-like substrings (e.g., UUIDs).
		for _, headerPattern := range sig.Headers {
			for key := range resp.Header {
				if strings.EqualFold(key, headerPattern) {
					return WAFResult{true, sig.Name, "header: " + key}
				}
			}
		}

		// Check body patterns (patterns pre-lowercased at init)
		for _, pattern := range sig.BodyPatternsLower {
			if strings.Contains(bodyLower, pattern) {
				return WAFResult{true, sig.Name, "body: " + pattern}
			}
		}
	}

	return WAFResult{Detected: false}
}

func init() {
	for i := range wafSignatures {
		sig := &wafSignatures[i]
		sig.BodyPatternsLower = make([]string, len(sig.BodyPatterns))
		for j, p := range sig.BodyPatterns {
			sig.BodyPatternsLower[j] = strings.ToLower(p)
		}
	}
}
