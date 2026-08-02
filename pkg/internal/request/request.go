// Package request provides shared HTTP request construction utilities.
package request

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
)

// MaxBodyRead limits how much of a multipart part body we read into memory.
const MaxBodyRead = 1 * 1024 * 1024 // 1MB

// CloneHeaders deep-copies a header map to prevent data races when
// multiple targets share the same underlying map.
func CloneHeaders(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// CloneCookies deep-copies a slice of cookies, preserving all fields.
// Use this instead of manual pointer-copy loops to avoid duplicating the
// clone idiom across packages (analyzer, scanner, cmd).
func CloneCookies(src []*http.Cookie) []*http.Cookie {
	if src == nil {
		return nil
	}
	dst := make([]*http.Cookie, len(src))
	for i, c := range src {
		if c != nil {
			cp := *c
			dst[i] = &cp
		}
	}
	return dst
}

// Pre-compiled regex for XML leaf-element text replacement (InjectBodyAll).
// Hoisted from per-payload call to avoid recompilation in hot path.
var xmlElementRe = regexp.MustCompile(`(<(\w+)[^>]*>)([^<]*)(</(\w+)>)`)

// ContentTypeKey is the HTTP header key for Content-Type.
const ContentTypeKey = "Content-Type"

// ApplyHeaders sets User-Agent, Content-Type, Cookies, Proxy-Authorization, and custom headers on a request.
// If User-Agent is not already set in target.Headers, the default UA or a random UA is used
// depending on the randomUA flag.
func ApplyHeaders(req *http.Request, target model.Target, randomUA bool) {
	if _, ok := target.Headers["User-Agent"]; !ok {
		if randomUA {
			req.Header.Set("User-Agent", httpclient.Pool.GetRandom())
		} else {
			req.Header.Set("User-Agent", httpclient.DefaultUA)
		}
	}
	if target.ProxyAuth != "" {
		req.Header.Set("Proxy-Authorization", target.ProxyAuth)
	}
	if target.Body != "" {
		if ct, ok := target.Headers["Content-Type"]; ok {
			req.Header.Set("Content-Type", ct)
		}
	}
	for _, c := range target.Cookies {
		req.AddCookie(c)
	}
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}
}

// HeaderMap converts http.Header to a simple map (first value only).
func HeaderMap(h http.Header) map[string]string {
	m := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// InjectBodyValue replaces a parameter value in a JSON, form-urlencoded, multipart, XML, or GraphQL body.
// For JSON bodies, supports dot-notation nested keys (e.g., "user.address.city")
// and array-index notation (e.g., "items[0].name").
// For multipart/form-data, replaces the named form field value.
// For XML, replaces the text content of the named element.
// For GraphQL, replaces the value of the named field in the query string.
// Returns the modified body string.
func InjectBodyValue(body, name, value string, headers map[string]string) string {
	ct := headers[ContentTypeKey]

	switch {
	case strings.Contains(ct, "application/json"):
		return injectBodyJSON(body, name, value)
	case strings.Contains(ct, "multipart/form-data"):
		return injectBodyMultipart(body, name, value, ct)
	case strings.Contains(ct, "application/xml"), strings.Contains(ct, "text/xml"):
		return injectBodyXML(body, name, value)
	case strings.Contains(ct, "application/graphql"):
		return injectBodyGraphQL(body, name, value)
	default:
		// form-urlencoded (or unknown — treat as form-urlencoded)
		return injectBodyFormURLEncoded(body, name, value)
	}
}

// injectBodyJSON handles JSON body injection.
// When the body is empty ({}) or the parameter doesn't exist,
// it creates the field to ensure payload reflection is testable.
func injectBodyJSON(body, name, value string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err == nil {
		path := parseKeyPath(name)
		// createMissing=true: allows injection into empty bodies ({})
		// and adding new fields that don't exist in the original request
		if setNestedValue(data, path, value, true) {
			if b, err := json.Marshal(data); err == nil {
				return string(b)
			}
		}
	}
	return body
}

// injectBodyFormURLEncoded handles form-urlencoded body injection.
func injectBodyFormURLEncoded(body, name, value string) string {
	values, err := url.ParseQuery(body)
	if err != nil {
		return body
	}
	values.Set(name, value)
	return values.Encode()
}

// multipartField holds the metadata and content of a parsed multipart field.
type multipartField struct {
	name     string
	filename string
	content  string
}

// injectBodyMultipart handles multipart/form-data body injection.
// Parses the multipart body, replaces the named field's value, and re-encodes.
func injectBodyMultipart(body, name, value, contentType string) string {
	fields := parseMultipartFields(body, contentType)
	if fields == nil {
		return body
	}

	var buf strings.Builder
	writer := multipart.NewWriter(&buf)
	writer.SetBoundary(extractBoundary(contentType))

	for _, f := range fields {
		partValue := f.content
		if f.name == name {
			partValue = value
		}

		var fw io.Writer
		var err error
		if f.filename != "" {
			fw, err = writer.CreateFormFile(f.name, f.filename)
		} else {
			fw, err = writer.CreateFormField(f.name)
		}
		if err != nil {
			return body
		}
		fw.Write([]byte(partValue))
	}
	writer.Close()
	return buf.String()
}

// parseMultipartFields reads all fields from a multipat body immediately,
// storing content before the reader advances past each part.
func parseMultipartFields(body, contentType string) []*multipartField {
	boundary := extractBoundary(contentType)
	if boundary == "" {
		return nil
	}
	mr := multipart.NewReader(strings.NewReader(body), boundary)
	var fields []*multipartField
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		content, err := io.ReadAll(io.LimitReader(p, MaxBodyRead))
		if err != nil {
			return nil
		}
		fields = append(fields, &multipartField{
			name:     p.FormName(),
			filename: p.FileName(),
			content:  string(content),
		})
	}
	return fields
}

// extractBoundary extracts the boundary string from a multipart Content-Type header.
// Uses mime.ParseMediaType for RFC-compliant parsing (handles quoted values with semicolons).
func extractBoundary(contentType string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return params["boundary"]
}

// injectBodyXML handles XML body injection.
// Finds the element matching the name and replaces its text content.
func injectBodyXML(body, name, value string) string {
	// Use simple regex-based replacement for XML element content.
	// Handles: <name>old</name> and <name attr="...">old</name>
	openTagRe := regexp.MustCompile(`(?i)(<` + regexp.QuoteMeta(name) + `(?:\s[^>]*)?>)(.*?)(</` + regexp.QuoteMeta(name) + `>)`)
	matches := openTagRe.FindStringSubmatchIndex(body)
	if matches == nil {
		return body
	}
	// Replace the content between open and close tags
	var buf strings.Builder
	buf.WriteString(body[:matches[4]])
	buf.WriteString(value)
	buf.WriteString(body[matches[5]:])
	return buf.String()
}

// injectBodyGraphQL handles GraphQL body injection.
// GraphQL POST bodies are JSON: {"query":"query { user(name: \"test\") { id } }", "variables":{...}}
// We inject into the query string by replacing field argument values.
func injectBodyGraphQL(body, name, value string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return body
	}
	query, ok := data["query"].(string)
	if !ok {
		return body
	}
	// Replace field argument: name: "old" or name: old or name:"old"
	re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(name) + `\s*:\s*"?[^"\s)]+"?`)
	newQuery := re.ReplaceAllStringFunc(query, func(match string) string {
		// Extract the part after the colon
		colonIdx := strings.Index(match, ":")
		if colonIdx < 0 {
			return match
		}
		prefix := match[:colonIdx+1]
		// Check if original used quotes
		rest := strings.TrimSpace(match[colonIdx+1:])
		if strings.HasPrefix(rest, `"`) {
			return prefix + ` "` + value + `"`
		}
		return prefix + ` ` + value
	})
	data["query"] = newQuery
	if b, err := json.Marshal(data); err == nil {
		return string(b)
	}
	return body
}

// parseKeyPath splits a dot-notation and bracket-notation key into segments.
// e.g., "user.address.city" → ["user", "address", "city"]
//       "items[0].name"     → ["items", "0", "name"]
func parseKeyPath(key string) []string {
	var segments []string
	var current strings.Builder
	for _, r := range key {
		switch r {
		case '.':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
		case '[':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
		case ']':
			// skip, number is added to current
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		segments = append(segments, current.String())
	}
	return segments
}

// setNestedValue walks the path in the data map and sets the value at the leaf.
// Supports dot-notation and bracket-notation array indices.
// If createMissing is true, intermediate maps are created for missing keys,
// allowing injection into empty bodies (e.g., {} → {"param":payload}).
// Returns true if the value was set, false otherwise.
func setNestedValue(data map[string]interface{}, path []string, value interface{}, createMissing bool) bool {
	if len(path) == 0 {
		return false
	}
	current := data
	for i := 0; i < len(path); i++ {
		key := path[i]
		if i == len(path)-1 {
			// Last segment — set the value
			current[key] = value
			return true
		}
		// Not last segment — descend into child
		next, ok := current[key]
		if !ok {
			if !createMissing {
				return false
			}
			// Create intermediate map and continue
			m := make(map[string]interface{})
			current[key] = m
			current = m
			continue
		}
		switch v := next.(type) {
		case map[string]interface{}:
			current = v
		case []interface{}:
			// Next segment must be an array index
			idx, err := strconv.Atoi(path[i+1])
			if err != nil || idx < 0 || idx >= len(v) {
				return false
			}
			i++ // consume the index segment
			if i == len(path)-1 {
				// Array index is the last segment — replace the element
				v[idx] = value
				return true
			}
			// Descend into the array element
			if m, ok := v[idx].(map[string]interface{}); ok {
				current = m
			} else {
				return false
			}
		default:
			return false
		}
	}
	return false
}

// InjectBodyAll replaces all leaf parameter values in a body with the given marker.
// For JSON bodies, recursively walks nested objects/arrays, preserving structure.
// For multipart, replaces all form field values.
// For XML, replaces all element text content.
// For GraphQL, replaces all field argument values in the query.
func InjectBodyAll(body, marker string, headers map[string]string) string {
	ct := headers[ContentTypeKey]

	switch {
	case strings.Contains(ct, "application/json"):
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(body), &data); err == nil {
			replaceLeaves(data, func(_ string, _ interface{}) (string, bool) {
				return marker, true
			})
			if b, err := json.Marshal(data); err == nil {
				return string(b)
			}
		}
		return body

	case strings.Contains(ct, "multipart/form-data"):
		fields := parseMultipartFields(body, ct)
		if fields == nil {
			return body
		}
		var buf strings.Builder
		writer := multipart.NewWriter(&buf)
		writer.SetBoundary(extractBoundary(ct))
		for _, f := range fields {
			var fw io.Writer
			var err error
			if f.filename != "" {
				fw, err = writer.CreateFormFile(f.name, f.filename)
			} else {
				fw, err = writer.CreateFormField(f.name)
			}
			if err != nil {
				return body
			}
			fw.Write([]byte(marker))
		}
		writer.Close()
		return buf.String()

	case strings.Contains(ct, "application/xml"), strings.Contains(ct, "text/xml"):
		// Go regexp doesn't support backreferences, so we match generically
		// and verify tag names match inside the replacement function.
		return xmlElementRe.ReplaceAllStringFunc(body, func(match string) string {
			m := xmlElementRe.FindStringSubmatch(match)
			if m != nil && m[2] == m[5] && m[3] != "" {
				return m[1] + marker + m[4]
			}
			return match
		})

	case strings.Contains(ct, "application/graphql"):
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(body), &data); err != nil {
			return body
		}
		query, ok := data["query"].(string)
		if !ok {
			return body
		}
		// Replace all string arguments in the query
		re := regexp.MustCompile(`:\s*"[^"]*"`)
		newQuery := re.ReplaceAllString(query, `: "`+marker+`"`)
		data["query"] = newQuery
		if b, err := json.Marshal(data); err == nil {
			return string(b)
		}
		return body

	default:
		// form-urlencoded
		values, err := url.ParseQuery(body)
		if err != nil {
			return body
		}
		for name := range values {
			values.Set(name, marker)
		}
		return values.Encode()
	}
}

// InjectBodyMarkers injects unique markers per parameter name into a body.
// Unlike InjectBodyAll which uses one marker for all fields, this allows
// per-parameter marker attribution: each field gets its own unique marker
// so the analyzer can determine exactly which parameter reflected.
// The markers map is param-name → marker. Fields not in the map are skipped.
func InjectBodyMarkers(body string, markers map[string]string, headers map[string]string) string {
	ct := headers[ContentTypeKey]

	switch {
	case strings.Contains(ct, "application/json"):
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(body), &data); err == nil {
			replaceLeaves(data, func(k string, _ interface{}) (string, bool) {
				m, ok := markers[k]
				return m, ok
			})
			if b, err := json.Marshal(data); err == nil {
				return string(b)
			}
		}
		return body

	case strings.Contains(ct, "multipart/form-data"):
		fields := parseMultipartFields(body, ct)
		if fields == nil {
			return body
		}
		var buf strings.Builder
		writer := multipart.NewWriter(&buf)
		writer.SetBoundary(extractBoundary(ct))
		for _, f := range fields {
			val := f.content
			if m, ok := markers[f.name]; ok {
				val = m
			}
			var fw io.Writer
			var err error
			if f.filename != "" {
				fw, err = writer.CreateFormFile(f.name, f.filename)
			} else {
				fw, err = writer.CreateFormField(f.name)
			}
			if err != nil {
				return body
			}
			fw.Write([]byte(val))
		}
		writer.Close()
		return buf.String()

	case strings.Contains(ct, "application/xml"), strings.Contains(ct, "text/xml"):
		// Single-pass replacement: one regex compilation, one body scan.
		// The generic pattern matches any element; the callback looks up the
		// tag name in the markers map to decide whether to replace content.
		return xmlElementRe.ReplaceAllStringFunc(body, func(match string) string {
			m := xmlElementRe.FindStringSubmatch(match)
			if m != nil && m[2] == m[5] && m[3] != "" {
				if marker, ok := markers[m[2]]; ok {
					return m[1] + marker + m[4]
				}
			}
			return match
		})

	case strings.Contains(ct, "application/graphql"):
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(body), &data); err != nil {
			return body
		}
		query, ok := data["query"].(string)
		if !ok {
			return body
		}
		// Single-pass: one regex matches any field:arg pattern, callback
		// dispatches via map lookup to find the right marker.
		graphqlFieldRe := regexp.MustCompile(`(?i)\b(\w+)\s*:\s*("?[^"\s)]+"?)`)
		query = graphqlFieldRe.ReplaceAllStringFunc(query, func(match string) string {
			parts := graphqlFieldRe.FindStringSubmatch(match)
			marker, ok := markers[parts[1]]
			if !ok {
				return match
			}
			colonIdx := strings.Index(match, ":")
			if colonIdx < 0 {
				return match
			}
			prefix := match[:colonIdx+1]
			rest := strings.TrimSpace(match[colonIdx+1:])
			if strings.HasPrefix(rest, `"`) {
				return prefix + ` "` + marker + `"`
			}
			return prefix + ` ` + marker
		})
		data["query"] = query
		if b, err := json.Marshal(data); err == nil {
			return string(b)
		}
		return body

	default:
		// form-urlencoded
		values, err := url.ParseQuery(body)
		if err != nil {
			return body
		}
		for name, marker := range markers {
			if _, ok := values[name]; ok {
				values.Set(name, marker)
			}
		}
		return values.Encode()
	}
}

// replaceLeafFn determines the replacement value for a leaf key.
// It receives the current key and value, and returns the replacement
// and true if the key should be replaced, or "", false to leave it.
type replaceLeafFn func(key string, val interface{}) (string, bool)

// replaceLeaves recursively walks a nested JSON structure and applies fn
// to each leaf key-value pair. Maps and arrays are traversed; when fn
// returns true the leaf is replaced with its returned string.
func replaceLeaves(data map[string]interface{}, fn replaceLeafFn) {
	for k, v := range data {
		switch val := v.(type) {
		case map[string]interface{}:
			replaceLeaves(val, fn)
		case []interface{}:
			for _, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					replaceLeaves(m, fn)
				}
			}
		default:
			if replacement, ok := fn(k, v); ok {
				data[k] = replacement
			}
		}
	}
}
