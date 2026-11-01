package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	xhtml "golang.org/x/net/html"
)

const redacted = "[REDACTED]"

var credentialPair = regexp.MustCompile(`(?i)["']?([a-z0-9_.-]*(?:token|secret|password|passwd|apikey|api_key|api-key|credential|csrf|session)[a-z0-9_.-]*|authorization|cookie|auth|sid|jwt|code|key)["']?\s*[:=]\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s&;,"'<>{}]+))`)
var authValue = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+([a-z0-9._~+/=-]+)`)
var reportURL = regexp.MustCompile(`https?://[^\s<>"']+`)

func sensitiveName(name string) bool {
	name = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, name)
	for _, part := range []string{"token", "secret", "password", "passwd", "authorization", "cookie", "apikey", "credential", "csrf", "session"} {
		if strings.Contains(name, part) {
			return true
		}
	}
	return name == "auth" || name == "sid" || name == "jwt" || name == "code" || strings.HasSuffix(name, "key")
}

// Unknown/custom headers may carry application-specific credentials. Retain only
// ordinary routing/representation metadata in safe HTTP evidence.
func publicHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-type", "content-length", "date", "server", "connection", "content-encoding", "transfer-encoding", "cache-control":
		return true
	}
	return false
}

type redactor struct {
	secrets map[string]bool
	replace *strings.Replacer
}

func (r *redactor) remember(value string) {
	if value != "" && value != redacted {
		r.secrets[value] = true
		if decoded, err := url.QueryUnescape(value); err == nil && decoded != "" {
			r.secrets[decoded] = true
		}
		r.secrets[html.UnescapeString(value)] = true
	}
}

func (r *redactor) collect(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if strings.Contains(strings.ToLower(key), "base64") {
				if text, ok := item.(string); ok {
					if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
						r.collectString(string(decoded))
					}
				}
			}
			r.collect(item)
		}
	case []any:
		for _, item := range v {
			r.collect(item)
		}
	case string:
		r.collectString(v)
	}
}

func (r *redactor) collectString(value string) {
	body := value
	head, tail, isHTTP := strings.Cut(value, "\r\n\r\n")
	if isHTTP {
		body = tail
	}
	var document any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&document) == nil {
		r.collectJSONCredentials(document, false)
	}
	if isHTTP {
		for _, line := range strings.Split(head, "\r\n")[1:] {
			name, contentType, ok := strings.Cut(line, ":")
			if !ok || !strings.EqualFold(name, "Content-Type") {
				continue
			}
			mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(contentType))
			if err != nil {
				continue
			}
			if mediaType == "application/x-www-form-urlencoded" {
				values, _ := url.ParseQuery(body)
				for key, items := range values {
					if sensitiveName(key) {
						for _, item := range items {
							r.remember(item)
						}
					}
				}
			}
			if mediaType == "multipart/form-data" && params["boundary"] != "" {
				parts := multipart.NewReader(strings.NewReader(body), params["boundary"])
				for {
					part, err := parts.NextPart()
					if err != nil {
						break
					}
					if sensitiveName(part.FormName()) {
						content, _ := io.ReadAll(io.LimitReader(part, 512*1024))
						r.remember(string(content))
					}
					part.Close()
				}
			}
		}
	}
	for _, match := range credentialPair.FindAllStringSubmatch(value, -1) {
		for _, item := range match[2:] {
			r.remember(item)
		}
	}
	for _, match := range authValue.FindAllStringSubmatch(value, -1) {
		r.remember(match[2])
		if strings.EqualFold(match[1], "Basic") {
			if decoded, err := base64.StdEncoding.DecodeString(match[2]); err == nil {
				if user, password, ok := strings.Cut(string(decoded), ":"); ok {
					r.remember(user)
					r.remember(password)
				}
			}
		}
	}
	for _, rawURL := range reportURL.FindAllString(value, -1) {
		r.collectURL(rawURL)
	}
	lines := strings.Split(value, "\n")
	if isHTTP {
		lines = strings.Split(head, "\r\n")[1:]
	}
	previousSecret := false
	for _, line := range lines {
		if isHTTP && previousSecret && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			r.remember(strings.TrimSpace(line))
			continue
		}
		key, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		previousSecret = ok && !publicHeader(key)
		if !ok || !(sensitiveName(key) || isHTTP && !publicHeader(key)) {
			continue
		}
		rest = strings.TrimSpace(rest)
		if strings.EqualFold(key, "Location") {
			r.collectURL(rest)
		}
		if strings.EqualFold(key, "Cookie") || strings.EqualFold(key, "Set-Cookie") {
			parts := strings.Split(rest, ";")
			if strings.EqualFold(key, "Set-Cookie") {
				parts = parts[:1]
			}
			for _, part := range parts {
				if _, val, ok := strings.Cut(part, "="); ok {
					r.remember(strings.Trim(strings.TrimSpace(val), `"`))
				}
			}
		} else {
			r.remember(rest)
		}
	}
	// HTML form/meta credentials may be reflected elsewhere in the report.
	z := xhtml.NewTokenizer(strings.NewReader(value))
	for kind := z.Next(); kind != xhtml.ErrorToken; kind = z.Next() {
		if kind != xhtml.StartTagToken && kind != xhtml.SelfClosingTagToken {
			continue
		}
		token := z.Token()
		secret := false
		for _, attr := range token.Attr {
			if (attr.Key == "name" || attr.Key == "id") && sensitiveName(attr.Val) || attr.Key == "type" && strings.EqualFold(attr.Val, "password") {
				secret = true
			}
		}
		if secret {
			for _, attr := range token.Attr {
				if attr.Key == "value" || attr.Key == "content" {
					r.remember(attr.Val)
				}
			}
		}
	}
}

func (r *redactor) collectURL(raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	if u.User != nil {
		r.remember(u.User.Username())
		password, _ := u.User.Password()
		r.remember(password)
	}
	fragment, _ := url.ParseQuery(u.Fragment)
	for _, values := range []url.Values{u.Query(), fragment} {
		for key, items := range values {
			if sensitiveName(key) {
				for _, item := range items {
					r.remember(item)
				}
			}
		}
	}
}

func (r *redactor) collectJSONCredentials(value any, secret bool) {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			r.collectJSONCredentials(item, secret || sensitiveName(key))
		}
	case []any:
		for _, item := range v {
			r.collectJSONCredentials(item, secret)
		}
	case string:
		if secret {
			r.remember(v)
		}
	case json.Number:
		if secret {
			r.remember(v.String())
		}
	}
}

func (r *redactor) compile() {
	forms := map[string]bool{}
	for secret := range r.secrets {
		encoded, _ := json.Marshal(secret)
		for _, form := range []string{secret, string(encoded[1 : len(encoded)-1]), url.QueryEscape(secret), url.PathEscape(secret), html.EscapeString(secret), base64.StdEncoding.EncodeToString([]byte(secret))} {
			forms[form] = true
			forms[url.QueryEscape(form)] = true
		}
	}
	keys := make([]string, 0, len(forms))
	for key := range forms {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) == len(keys[j]) {
			return keys[i] < keys[j]
		}
		return len(keys[i]) > len(keys[j])
	})
	pairs := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		pairs = append(pairs, key, redacted)
	}
	r.replace = strings.NewReplacer(pairs...)
}

func (r *redactor) text(value string) string {
	value = reportURL.ReplaceAllStringFunc(value, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		changed := u.User != nil
		u.User = nil
		query := u.Query()
		for key := range query {
			if sensitiveName(key) {
				query[key] = []string{redacted}
				changed = true
			}
		}
		if !changed {
			return raw
		}
		u.RawQuery = query.Encode()
		return u.String()
	})
	return r.replace.Replace(value)
}

func safeHTTP(value string) string {
	if value == "" {
		return ""
	}
	head, body, hasBody := strings.Cut(value, "\r\n\r\n")
	sep := "\r\n"
	if !hasBody {
		head, body, hasBody = strings.Cut(value, "\n\n")
		sep = "\n"
	}
	if !hasBody {
		return "[REDACTED: unstructured HTTP evidence]"
	}
	lines := strings.Split(head, sep)
	previousSecret := false
	for i := 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], " ") || strings.HasPrefix(lines[i], "\t") {
			if previousSecret {
				lines[i] = " " + redacted
			}
			continue
		}
		key, _, ok := strings.Cut(lines[i], ":")
		previousSecret = ok && !publicHeader(key)
		if previousSecret {
			lines[i] = key + ": " + redacted
		}
	}
	if body != "" {
		body = "[REDACTED HTTP BODY]"
	}
	return strings.Join(lines, sep) + sep + sep + body
}

func (r *redactor) scrub(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			// These are schema identifiers/enums, never credential-bearing content.
			// A cookie value equal to "completed" or "1" must not change status/schema.
			switch strings.ToLower(key) {
			case "schemaversion", "type", "status", "severity", "paramtype", "scheme", "stage", "kind", "analysismethod", "detectionmethod", "analysis_method", "detection_method", "source", "sink":
				continue
			}
			if text, ok := item.(string); ok {
				switch strings.ToLower(key) {
				case "requestbase64", "responsebase64", "initialrequestbase64", "request_base64", "response_base64", "initial_request_base64", "screenshotpath", "screenshot_path":
					v[key] = ""
					continue
				case "reflection", "context":
					if text != "" {
						v[key] = "[REDACTED RESPONSE SNIPPET]"
					}
					continue
				case "rawrequest", "rawresponse", "request", "response", "initial_request":
					item = safeHTTP(text)
				}
			}
			v[key] = r.scrub(item)
		}
		return v
	case []any:
		for i, item := range v {
			v[i] = r.scrub(item)
		}
		return v
	case string:
		return r.text(v)
	default:
		return value
	}
}

// redactedCopy serializes only the report projection, never mutating scan or
// replay evidence. UseNumber preserves large integer counters in the schema.
func redactedCopy(data *ScanData) (*ScanData, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	r := redactor{secrets: map[string]bool{}}
	r.collect(document)
	r.compile()
	encoded, err = json.Marshal(r.scrub(document))
	if err != nil {
		return nil, err
	}
	var out ScanData
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, err
	}
	// Prebuilt commands can carry credentials absent from captured evidence.
	// Derive the safe command only from already-redacted request/URL fields.
	for i := range out.Findings {
		finding := &out.Findings[i]
		finding.CurlPOC = findingCurl(*finding)
		if finding.CurlPOC == "" && finding.RawRequest == "" {
			finding.CurlPOC = buildCurlPOC(finding.URL, finding.Parameter, finding.Payload, finding.ParamType)
		}
	}
	return &out, nil
}
