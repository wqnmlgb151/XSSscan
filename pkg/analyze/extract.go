package analyze

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"mime"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
)

// ExtractParameters extracts all injectable parameters from a Target.
// discoverHeaders controls whether dangerous headers (X-Forwarded-Host, etc.)
// are auto-added as injection points.
func ExtractParameters(target model.Target, discoverHeaders bool) []model.Parameter {
	var params []model.Parameter

	// 1. Query parameters
	if u, err := url.Parse(target.URL); err == nil {
		for name, values := range u.Query() {
			value := ""
			if len(values) > 0 {
				value = values[0]
			}
			params = append(params, model.Parameter{
				Name:  name,
				Value: value,
				Type:  model.ParamQuery,
			})
		}
	}

	// 2. Body parameters (POST/PUT/PATCH)
	if target.Body != "" && (target.Method == "POST" || target.Method == "PUT" || target.Method == "PATCH") {
		bodyParams := extractBodyParams(target.Body, target.Headers)
		params = append(params, bodyParams...)
	}

	// 3. Header parameters — test ALL user-provided headers as injectable points.
	// This covers both known XSS vectors (Referer, X-Forwarded-Host) and
	// custom application headers (X-API-Key, X-Tenant-ID, etc.) that may reflect.
	for h, val := range target.Headers {
		if val != "" {
			params = append(params, model.Parameter{
				Name:  h,
				Value: val,
				Type:  model.ParamHeader,
			})
		}
	}

	// 4. Cookie parameters
	for _, c := range target.Cookies {
		params = append(params, model.Parameter{
			Name:  c.Name,
			Value: c.Value,
			Type:  model.ParamCookie,
		})
	}

	// 5. Path parameters — extract dynamic path segments
	pathParams := extractPathParams(target.URL)
	params = append(params, pathParams...)

	// 5b. Dangerous headers auto-discovery — headers historically vulnerable to XSS reflection
	if discoverHeaders {
		dangerousHeaders := []string{
			"X-Forwarded-Host", "X-Forwarded-For", "X-Forwarded-Proto",
			"X-Original-URL", "X-Rewrite-URL", "Referer", "User-Agent",
			"CF-Connecting-IP", "True-Client-IP", "X-Real-IP",
		}
		for _, h := range dangerousHeaders {
			// Only add if not already present in user-provided headers
			if _, exists := target.Headers[h]; !exists {
				params = append(params, model.Parameter{
					Name:  h,
					Value: "xsscan-test",
					Type:  model.ParamHeader,
				})
			}
		}
	}

	// 6. XML attribute injection points (for XML bodies)
	if target.Body != "" {
		ct := target.Headers[request.ContentTypeKey]
		if strings.Contains(ct, "xml") || strings.HasPrefix(strings.TrimSpace(target.Body), "<") {
			xmlParams := extractXMLParams(target.Body)
			params = append(params, xmlParams...)
		}
	}

	return params
}

// extractBodyParams parses body based on Content-Type
func extractBodyParams(body string, headers map[string]string) []model.Parameter {
	var params []model.Parameter

	ct := headers[request.ContentTypeKey]
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType = ct
	}

	switch {
	case strings.Contains(mediaType, "application/json"):
		params = extractJSONParams(body)
	case strings.Contains(mediaType, "application/x-www-form-urlencoded"):
		params = extractFormParams(body)
	default:
		// Try form-urlencoded as fallback
		params = extractFormParams(body)
	}

	return params
}

func extractJSONParams(body string) []model.Parameter {
	var params []model.Parameter

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return params
	}

	extractJSONParamsRecursive(data, "", &params)
	return params
}

func extractJSONParamsRecursive(data map[string]interface{}, prefix string, params *[]model.Parameter) {
	extractJSONParamsRecursiveWithDepth(data, prefix, params, 0)
}

func extractJSONParamsRecursiveWithDepth(data map[string]interface{}, prefix string, params *[]model.Parameter, depth int) {
	if depth > 32 {
		return // Prevent stack overflow on deeply nested JSON
	}
	for k, v := range data {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]interface{}:
			extractJSONParamsRecursiveWithDepth(val, fullKey, params, depth+1)
		case []interface{}:
			for i, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					extractJSONParamsRecursiveWithDepth(m, fmt.Sprintf("%s[%d]", fullKey, i), params, depth+1)
				} else {
					*params = append(*params, model.Parameter{
						Name:  fmt.Sprintf("%s[%d]", fullKey, i),
						Value: fmt.Sprintf("%v", item),
						Type:  model.ParamBody,
					})
				}
			}
		default:
			*params = append(*params, model.Parameter{
				Name:  fullKey,
				Value: fmt.Sprintf("%v", val),
				Type:  model.ParamBody,
			})
		}
	}
}

func extractFormParams(body string) []model.Parameter {
	var params []model.Parameter

	values, err := url.ParseQuery(body)
	if err != nil {
		return params
	}

	for name, vals := range values {
		value := ""
		if len(vals) > 0 {
			value = vals[0]
		}
		params = append(params, model.Parameter{
			Name:  name,
			Value: value,
			Type:  model.ParamBody,
		})
	}
	return params
}

// pathSegmentPattern matches framework-style dynamic path tokens.
// Supports: {id} (Spring), :id (Express), <id> (Django), [id] (Next.js).
var pathSegmentPattern = regexp.MustCompile(`^[\:<\{\[]([^>\}\]]+)[\>\}\]]$`)

// dynamicSlugs are common URL segments that look dynamic but are static.
var dynamicSlugs = map[string]bool{
	"api": true, "v1": true, "v2": true, "v3": true, "v4": true,
	"www": true, "cdn": true, "static": true, "assets": true,
	"js": true, "css": true, "img": true, "images": true, "fonts": true,
	"download": true, "uploads": true, "media": true, "public": true,
	"admin": true, "auth": true, "login": true, "logout": true,
}

// extractPathParams discovers injectable path segments.
// Supports patterns: /api/{id}/profile, /api/:id/profile, /api/v1/<id>/profile
// Also detects non-numeric, non-UUID segments that appear dynamic.
func extractPathParams(targetURL string) []model.Parameter {
	var params []model.Parameter

	u, err := url.Parse(targetURL)
	if err != nil {
		return params
	}

	segments := strings.Split(u.Path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}

		// Skip purely numeric segments (likely IDs, not injection points)
		if isNumericSegment(seg) {
			continue
		}

		// Skip UUIDs
		if isUUID(seg) {
			continue
		}

		// Skip common static slugs
		if dynamicSlugs[strings.ToLower(seg)] {
			continue
		}

		// Check framework-style patterns: {id}, :id, <id>, [id]
		if matches := pathSegmentPattern.FindStringSubmatch(seg); matches != nil {
			paramName := matches[1]
			params = append(params, model.Parameter{
				Name:  paramName,
				Value: seg,
				Type:  model.ParamPath,
			})
			continue
		}

		// Heuristic: segments with non-alphanumeric chars (excluding - and _)
		// that aren't recognized as static are likely dynamic
		if isLikelyDynamicSegment(seg) {
			params = append(params, model.Parameter{
				Name:  fmt.Sprintf("path[%d]", i),
				Value: seg,
				Type:  model.ParamPath,
			})
		}
	}

	return params
}

// isNumericSegment reports whether a path segment is purely numeric.
func isNumericSegment(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return len(s) > 0
}

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// isUUID reports whether a string looks like a UUID.
func isUUID(s string) bool {
	return uuidPattern.MatchString(s)
}

// isLikelyDynamicSegment uses heuristics to detect non-static path segments.
func isLikelyDynamicSegment(s string) bool {
	if len(s) < 2 || len(s) > 60 {
		return false
	}
	// Has mixed case or special chars — likely dynamic
	hasLower := false
	hasUpper := false
	hasSpecial := false
	for _, r := range s {
		if unicode.IsLower(r) {
			hasLower = true
		}
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if r == '+' || r == '~' || r == '!' || r == '@' || r == '$' {
			hasSpecial = true
		}
	}
	// Mixed case or special chars suggest dynamic content
	return (hasLower && hasUpper) || hasSpecial
}

// xmlAttr represents an injectable XML attribute.
type xmlAttr struct {
	XMLName xml.Name
	Attr    []xml.Attr `xml:",any,attr"`
	Content string      `xml:",chardata"`
}

// extractXMLParams discovers injectable XML element text AND attribute values.
func extractXMLParams(body string) []model.Parameter {
	var params []model.Parameter

	// Walk XML tokens to find elements with text content AND attributes
	decoder := xml.NewDecoder(strings.NewReader(body))
	var currentElement string
	var elementStack []string

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			currentElement = t.Name.Local
			elementStack = append(elementStack, currentElement)

			// Extract attributes as injection points
			for _, attr := range t.Attr {
				if attr.Value != "" && len(attr.Value) > 0 {
					paramName := fmt.Sprintf("%s@%s", currentElement, attr.Name.Local)
					params = append(params, model.Parameter{
						Name:  paramName,
						Value: attr.Value,
						Type:  model.ParamBody,
					})
				}
			}

		case xml.EndElement:
			if len(elementStack) > 0 {
				elementStack = elementStack[:len(elementStack)-1]
			}
			if len(elementStack) > 0 {
				currentElement = elementStack[len(elementStack)-1]
			}

		case xml.CharData:
			content := strings.TrimSpace(string(t))
			if content != "" && currentElement != "" {
				paramName := fmt.Sprintf("%s#text", currentElement)
				params = append(params, model.Parameter{
					Name:  paramName,
					Value: content,
					Type:  model.ParamBody,
				})
			}
		}
	}

	return params
}
