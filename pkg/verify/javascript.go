package verify

import (
	"net/url"
	"strings"

	"github.com/wqnmlgb151/XSSscan/pkg/jsanalysis"
	"golang.org/x/net/html"
)

// Keep repeated evidence queries local to one unchanged document/candidate.
// Nested documents must create their own probe; no scan state is shared.
func memoizedResponseJSCall(body, candidate string) func() (bool, string) {
	checked, confirmed, parseError := false, false, ""
	return func() (bool, string) {
		if !checked {
			confirmed, parseError = responseJSCall(body, candidate)
			checked = true
		}
		return confirmed, parseError
	}
}

func candidateJSCall(source, candidate string, handler bool) (bool, string) {
	if candidate == "" {
		return false, ""
	}
	a := jsanalysis.Parse(source, handler)
	if a.Error != "" {
		return false, a.Error
	}
	for from, checks := 0, 0; from < len(source); checks++ {
		if checks >= maxContextChecks {
			return false, "JavaScript candidate occurrence analysis limit exceeded"
		}
		i := strings.Index(source[from:], candidate)
		if i < 0 {
			break
		}
		i += from
		if a.HasCallStartingIn(i, i+len(candidate)) {
			return true, ""
		}
		from = i + len(candidate)
	}
	return false, ""
}

// responseJSCall ties a parsed call to the candidate's bytes, never to a
// dialog-looking string or an unrelated call elsewhere on the page.
func responseJSCall(body, p string) (bool, string) {
	if p == "" {
		return false, ""
	}
	var spans []reflectionSpan
	for from := 0; from < len(body); {
		i := strings.Index(body[from:], p)
		if i < 0 {
			break
		}
		i += from
		spans = append(spans, reflectionSpan{i, i + len(p)})
		if len(spans) > 8192 {
			return false, "JavaScript candidate occurrence analysis limit exceeded"
		}
		from = i + len(p)
	}
	spanIndex := 0
	checks := 0
	t := html.NewTokenizer(strings.NewReader(body))
	position := 0
	inScript, executable := false, false
	scriptMode := jsanalysis.ScriptMode
	templateDepth := 0
	rawTextElement := ""
	var parseError string
	for {
		tt := t.Next()
		if tt == html.ErrorToken {
			break
		}
		start := position
		raw := string(t.Raw())
		position += len(raw)
		token := t.Token()
		if tt == html.StartTagToken {
			if token.Data == "template" {
				templateDepth++
			}
			switch token.Data {
			case "textarea", "title", "xmp", "iframe", "noscript", "noframes", "plaintext":
				rawTextElement = token.Data
			}
		}
		if tt == html.EndTagToken {
			if token.Data == "template" && templateDepth > 0 {
				templateDepth--
			}
			if token.Data == rawTextElement {
				rawTextElement = ""
			}
		}
		if tt == html.StartTagToken && token.Data == "script" {
			inScript = true
			executable = executableScript(token) && !scriptHasSource(token)
			scriptMode = scriptSourceMode(token)
		}
		if tt == html.EndTagToken && token.Data == "script" {
			inScript = false
		}
		if tt == html.TextToken && inScript && executable && templateDepth == 0 && rawTextElement == "" {
			for spanIndex < len(spans) && spans[spanIndex].end <= start {
				spanIndex++
			}
			if spanIndex >= len(spans) || spans[spanIndex].start >= position {
				continue
			}
			a := jsanalysis.ParseWithMode(raw, scriptMode)
			for j := spanIndex; j < len(spans) && spans[j].start < position; j++ {
				s := spans[j]
				checks++
				if checks > 64 {
					return false, "JavaScript candidate occurrence analysis limit exceeded"
				}
				if a.Error != "" {
					parseError = a.Error
				}
				if a.HasCallStartingIn(max(0, s.start-start), min(len(raw), s.end-start)) {
					return true, ""
				}
			}

		}
		if (tt == html.StartTagToken || tt == html.SelfClosingTagToken) && templateDepth == 0 && rawTextElement == "" {
			seen := make(map[string]bool)
			for _, attr := range token.Attr {
				if seen[attr.Key] {
					continue
				}
				seen[attr.Key] = true
				if executableURLAttribute(attr) && strings.HasPrefix(strings.ToLower(strings.TrimSpace(attr.Val)), "javascript:") && strings.Contains(attr.Val, p) {
					source := strings.TrimSpace(attr.Val)[len("javascript:"):]
					candidate := p
					if strings.HasPrefix(strings.ToLower(candidate), "javascript:") {
						candidate = candidate[len("javascript:"):]
					}
					if decoded, err := url.PathUnescape(source); err == nil {
						source = decoded
					}
					if decoded, err := url.PathUnescape(candidate); err == nil {
						candidate = decoded
					}
					if confirmed, problem := candidateJSCall(source, candidate, false); confirmed {
						return true, ""
					} else if problem != "" {
						parseError = problem
					}
				}
				if !strings.HasPrefix(attr.Key, "on") {
					continue
				}
				if !strings.Contains(attr.Val, p) {
					continue
				}
				a := jsanalysis.Parse(attr.Val, true)
				if a.Error != "" {
					parseError = a.Error
				}
				for from := 0; from < len(attr.Val); {
					i := strings.Index(attr.Val[from:], p)
					if i < 0 {
						break
					}
					i += from
					from = i + len(p)
					checks++
					if checks > 64 {
						return false, "JavaScript candidate occurrence analysis limit exceeded"
					}
					if a.HasCallStartingIn(i, i+len(p)) {
						return true, ""
					}
				}
			}
		}
	}
	return false, parseError
}

func scriptSourceMode(token html.Token) jsanalysis.SourceMode {
	for _, a := range token.Attr {
		if a.Key == "type" {
			if strings.EqualFold(strings.TrimSpace(a.Val), "module") {
				return jsanalysis.ModuleMode
			}
			break
		}
	}
	return jsanalysis.ScriptMode
}
