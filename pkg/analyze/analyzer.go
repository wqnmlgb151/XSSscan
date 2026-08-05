package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	stdctx "context"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/internal/text"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

type Analyzer struct {
	reflectionAnalyzer *ReflectionAnalyzer
	contextDetector    *ctx.Detector
	frameworkDetector  *FrameworkDetector
	cspAnalyzer        *CSPAnalyzer
	client             *http.Client
	discoverHeaders    bool
}

type AnalysisResult struct {
	Target          model.Target
	InjectionPoints []model.InjectionPoint
	Frameworks      []FrameworkInfo
	CSP             *CSPPolicy
}

func NewAnalyzer(client *http.Client) *Analyzer {
	if client == nil {
		client = httpclient.NewClient(30 * time.Second, nil)
	}
	// Set SSRF-aware redirect validation once at construction.
	// Previously sendRequest shallow-copied the entire http.Client on every
	// call just to override CheckRedirect — needlessly copying mutex state.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		if err := ssrfguard.IsURLTargetAllowed(req.URL.String()); err != nil {
			return fmt.Errorf("redirect blocked: %w", err)
		}
		return nil
	}
	return &Analyzer{
		reflectionAnalyzer: NewReflectionAnalyzer(),
		contextDetector:    ctx.NewDetector(),
		frameworkDetector:  NewFrameworkDetector(),
		cspAnalyzer:        NewCSPAnalyzer(),
		client:             client,
	}
}

func (a *Analyzer) Analyze(gtx stdctx.Context, target model.Target) (*AnalysisResult, error) {
	result := &AnalysisResult{Target: target}

	params := ExtractParameters(target, a.discoverHeaders)
	if len(params) == 0 {
		return result, nil
	}

	// Generate unique markers per parameter for correct reflection attribution.
	// This ensures each reflection in the response maps to the exact parameter
	// that caused it, preventing cross-parameter contamination where one
	// parameter's reflection is wrongly attributed to another.
	paramMarkers := make(map[string]string, len(params))
	for _, p := range params {
		paramMarkers[paramKey(p)] = GenerateMarker()
	}

	preserveAuth := hasAuthCredentials(target)
	modifiedTarget := injectPerParamMarkers(target, paramMarkers, preserveAuth)

	resp, err := a.sendRequest(gtx, modifiedTarget)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
	if err != nil {
		return nil, err
	}
	bodyStr := string(body)

	// WAF block detection: if the combined-marker request was blocked (403/406),
	// the response body won't contain any reflections. Fall back to per-parameter
	// analysis requests so that non-offending parameters are still scanned.
	if isWAFBlockResponse(resp, bodyStr) {
		return a.analyzePerParam(gtx, target, params, paramMarkers, preserveAuth)
	}

	result.Frameworks = a.frameworkDetector.Detect(resp, bodyStr)
	result.CSP = a.cspAnalyzer.Parse(request.HeaderMap(resp.Header))

	// Detect JSON responses for JSON-specific context analysis.
	isJSON := false
	var jsonValid bool
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		lower := strings.ToLower(ct)
		if strings.Contains(lower, "json") {
			isJSON = true
			// Validate JSON structure once before the reflection loop.
			var data interface{}
			jsonValid = json.Unmarshal([]byte(bodyStr), &data) == nil
		}
	}

	// Pre-compute URL-decoded body once for all parameters' fuzzy reflection checks.
	// Without this, each parameter's miss triggers a full-body URL-decode + search.
	var decodedBody string
	if strings.Contains(bodyStr, "%") {
		if d, err := url.QueryUnescape(bodyStr); err == nil && d != bodyStr {
			decodedBody = d
		}
	}

	for _, param := range params {
		marker := paramMarkers[paramKey(param)]
		reflections := a.reflectionAnalyzer.FindReflections(bodyStr, model.Parameter{
			Name:  param.Name,
			Value: marker,
		}, decodedBody)
		if len(reflections) == 0 {
			continue
		}
		for _, ref := range reflections {
			var contexts []ctx.Context

			if isJSON {
				// For JSON responses, detect JSON string context.
				jsonCtx := detectJSONContext(bodyStr, ref.Offset, marker, jsonValid)
				if jsonCtx != nil {
					contexts = []ctx.Context{*jsonCtx}
				}
			}

			if len(contexts) == 0 {
				// Fall back to HTML context detection for non-JSON responses
				// or when JSON parsing fails.
				refl := ctx.Reflection{
					Content:    bodyStr,
					Offset:     ref.Offset,
					ParamValue: marker,
					StatusCode: resp.StatusCode,
				}
				htmlContexts, err := a.contextDetector.Detect(refl)
				if err != nil {
					return nil, fmt.Errorf("context detection failed for %s: %w", param.Name, err)
				}
				contexts = htmlContexts
			}

			if len(contexts) == 0 {
				continue
			}
			result.InjectionPoints = append(result.InjectionPoints, model.InjectionPoint{
				Target:     target,
				Parameter:  param,
				Contexts:   contexts,
				Reflection: ref,
			})
		}
	}
	return result, nil
}

// detectJSONContext determines if a reflection point is inside a JSON string value.
// It checks whether the marker appears within a JSON string (odd number of
// unescaped double-quotes before the marker). The jsonValid parameter is a
// pre-computed JSON validity check (parsed once before the reflection loop).
func detectJSONContext(body string, offset int, marker string, jsonValid bool) *ctx.Context {
	// Use the provided offset from the caller's reflection search instead of
	// re-scanning with strings.Index. The offset points to the specific
	// reflection occurrence, while strings.Index would return the first match
	// (which could be a different occurrence).
	idx := offset
	if idx < 0 || idx >= len(body) {
		return nil
	}

	// Check if we're inside a JSON string value by counting quotes before the marker.
	// Odd number of unescaped double-quotes means we're inside a string value.
	segment := body[:idx]
	quoteCount := 0
	for i := 0; i < len(segment); i++ {
		if segment[i] == '"' && (i == 0 || segment[i-1] != '\\') {
			quoteCount++
		}
	}
	if quoteCount%2 == 0 {
		return nil
	}

	if !jsonValid {
		return nil
	}

	return &ctx.Context{
		Type:      ctx.ContextJSONValue,
		Raw:       text.Snippet(body, marker, 50),
		Enclosed:  true,
		QuoteChar: "\"",
		Priority:  5,
	}
}

// wafBlockPatterns are response body snippets that indicate a WAF block page.
// Used to detect when the analysis-phase request was blocked by a WAF.
var wafBlockPatterns = []string{
	"attention required", "cloudflare", "cf-browser-verification",
	"request blocked", "aws waf", "access denied",
	"not acceptable!", "modsecurity", "incapsula", "imperva",
	"sucuri", "wordfence", "your access to this site has been limited",
	"the requested url was rejected", "bigip",
}

// isWAFBlockResponse detects if the analysis-phase response is a WAF block page
// rather than the actual application response. A 403/406 status combined with
// known WAF body patterns indicates the request was blocked.
func isWAFBlockResponse(resp *http.Response, body string) bool {
	if resp.StatusCode != 403 && resp.StatusCode != 406 && resp.StatusCode != 503 {
		return false
	}
	bodyLower := strings.ToLower(body)
	for _, pattern := range wafBlockPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}
	return false
}

// analyzePerParam falls back to per-parameter analysis when the combined-marker
// request was blocked by a WAF. Each parameter gets its own request with only
// its marker injected, isolating offending parameters from clean ones.
func (a *Analyzer) analyzePerParam(gtx stdctx.Context, target model.Target, params []model.Parameter, markers map[string]string, preserveAuth bool) (*AnalysisResult, error) {
	result := &AnalysisResult{Target: target}

	// Use a baseline request (original values) for framework/CSP detection
	baselineTarget := injectPerParamMarkers(target, map[string]string{}, false)
	baselineResp, err := a.sendRequest(gtx, baselineTarget)
	if err == nil && baselineResp != nil && baselineResp.Body != nil {
		baselineBody, err := io.ReadAll(io.LimitReader(baselineResp.Body, httpclient.MaxResponseSize))
		if err != nil {
			baselineBody = nil // non-fatal: framework/CSP detection skips without baseline
		}
		baselineResp.Body.Close()
		result.Frameworks = a.frameworkDetector.Detect(baselineResp, string(baselineBody))
		result.CSP = a.cspAnalyzer.Parse(request.HeaderMap(baselineResp.Header))
	}

	for _, param := range params {
		key := paramKey(param)
		marker := markers[key]

		// Build a single-param marker map
		singleMarker := map[string]string{key: marker}
		modifiedTarget := injectPerParamMarkers(target, singleMarker, preserveAuth)

		resp, err := a.sendRequest(gtx, modifiedTarget)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyStr := string(body)

		// Skip if this parameter individually triggers WAF
		if isWAFBlockResponse(resp, bodyStr) {
			continue
		}

		// Pre-compute decoded body for this per-param response
		var decodedPerBody string
		if strings.Contains(bodyStr, "%") {
			if d, err := url.QueryUnescape(bodyStr); err == nil && d != bodyStr {
				decodedPerBody = d
			}
		}

		reflections := a.reflectionAnalyzer.FindReflections(bodyStr, model.Parameter{
			Name:  param.Name,
			Value: marker,
		}, decodedPerBody)
		if len(reflections) == 0 {
			continue
		}

		for _, ref := range reflections {
			refl := ctx.Reflection{
				Content:    bodyStr,
				Offset:     ref.Offset,
				ParamValue: marker,
				StatusCode: resp.StatusCode,
			}
			contexts, err := a.contextDetector.Detect(refl)
			if err != nil {
				continue
			}
			if len(contexts) == 0 {
				continue
			}
			result.InjectionPoints = append(result.InjectionPoints, model.InjectionPoint{
				Target:     target,
				Parameter:  param,
				Contexts:   contexts,
				Reflection: ref,
			})
		}
	}
	return result, nil
}

// paramKey returns a unique key for a parameter combining its type and name.
// This disambiguates parameters with the same name across injection points
// (e.g., query "id" vs body "id").
func paramKey(p model.Parameter) string {
	return string(p.Type) + ":" + p.Name
}

func (a *Analyzer) sendRequest(gtx stdctx.Context, target model.Target) (*http.Response, error) {
	// SSRF protection: validate target URL before making the request
	if err := ssrfguard.IsURLTargetAllowed(target.URL); err != nil {
		return nil, fmt.Errorf("ssrf blocked: %w", err)
	}

	var bodyReader io.Reader
	if target.Body != "" {
		bodyReader = strings.NewReader(target.Body)
	}
	req, err := http.NewRequestWithContext(gtx, target.HTTPMethod(), target.URL, bodyReader)
	if err != nil {
		return nil, err
	}
	request.ApplyHeaders(req, target, false)

	return a.client.Do(req)
}

// authSafeHeaders are headers that must be preserved during marker injection
// to avoid breaking authenticated scans. Replacing these with a marker causes
// the server to respond with a login redirect → zero reflections → false negative.
var authSafeHeaders = map[string]bool{
	"Authorization": true,
	"Cookie":        true,
	"X-API-Key":     true,
	"X-CSRF-Token":  true,
	"X-XSRF-Token":  true,
}

// authSafeCookies are session/auth cookie names preserved during analysis.
// Only these cookie values are kept; other cookies still get the marker.
var authSafeCookies = map[string]bool{
	"session":     true,
	"sid":         true,
	"token":       true,
	"jwt":         true,
	"auth":        true,
	"PHPSESSID":   true,
	"JSESSIONID":  true,
	"ASPSESSIONID": true,
	"connect.sid": true,
}

// injectPerParamMarkers injects unique markers per parameter into the target.
// Each parameter (query, body, header, cookie) gets its own unique marker value,
// enabling correct reflection attribution in the response.
// When preserveAuth is true, auth-critical headers and session cookies keep
// their original values so authenticated scans actually reach protected endpoints.
func injectPerParamMarkers(target model.Target, markers map[string]string, preserveAuth bool) model.Target {
	u, err := url.Parse(target.URL)
	if err != nil {
		return target
	}
	values := u.Query()
	for name := range values {
		key := paramKey(model.Parameter{Name: name, Type: model.ParamQuery})
		if m, ok := markers[key]; ok {
			values.Set(name, m)
		}
	}
	u.RawQuery = values.Encode()
	target.URL = u.String()

	if target.Body != "" {
		target.Body = request.InjectBodyMarkers(target.Body, markers, target.Headers)
	}

	// Inject header parameters — clone map to avoid mutating caller.
	// When preserveAuth is true, auth-critical headers keep their original values.
	clonedHeaders := make(map[string]string, len(target.Headers))
	for k, v := range target.Headers {
		if preserveAuth && authSafeHeaders[k] {
			clonedHeaders[k] = v
		} else {
			key := paramKey(model.Parameter{Name: k, Type: model.ParamHeader})
			if m, ok := markers[key]; ok {
				clonedHeaders[k] = m
			} else {
				clonedHeaders[k] = v
			}
		}
	}
	target.Headers = clonedHeaders

	// Inject cookie parameters — clone slice to avoid mutating caller.
	// Session/auth cookies are preserved when preserveAuth is true.
	clonedCookies := request.CloneCookies(target.Cookies)
	for _, c := range clonedCookies {
		if preserveAuth && authSafeCookies[c.Name] {
			continue
		}
		if m, ok := markers[paramKey(model.Parameter{Name: c.Name, Type: model.ParamCookie})]; ok {
			c.Value = m
		}
	}
	target.Cookies = clonedCookies

	return target
}

// hasAuthCredentials returns true if the target has authentication headers or
// session cookies that should be preserved during analysis-phase requests.
func hasAuthCredentials(target model.Target) bool {
	for k := range target.Headers {
		if authSafeHeaders[k] {
			return true
		}
	}
	for _, c := range target.Cookies {
		if c != nil && authSafeCookies[c.Name] {
			return true
		}
	}
	return false
}

// MarkerPrefix is the prefix for all reflection/stored detection markers.
const MarkerPrefix = "xsscan"

// MarkerRandomLen is the number of random chars appended to MarkerPrefix.
const MarkerRandomLen = 12

// GenerateMarker produces a unique marker for detection (reflection or stored).
// Format: MarkerPrefix + MarkerRandomLen random alphanumeric chars.
func GenerateMarker() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, MarkerRandomLen)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return MarkerPrefix + string(b)
}
