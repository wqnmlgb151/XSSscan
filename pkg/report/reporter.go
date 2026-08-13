package report

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/xsscan/xsscan/pkg/internal/text"
	"github.com/xsscan/xsscan/pkg/model"
)

type OutputFormat string

const (
	FormatJSON     OutputFormat = "json"
	FormatHTML     OutputFormat = "html"
	FormatMarkdown OutputFormat = "markdown"
	FormatSARIF    OutputFormat = "sarif"
	FormatJUnit    OutputFormat = "junit"
)

type Reporter struct{}

func NewReporter() *Reporter {
	return &Reporter{}
}

func (r *Reporter) Generate(data *ScanData, format OutputFormat) ([]byte, error) {
	switch format {
	case FormatJSON:
		return json.MarshalIndent(data, "", "  ")
	case FormatMarkdown:
		return []byte(r.generateMarkdown(data)), nil
	case FormatHTML:
		return []byte(r.generateHTML(data)), nil
	case FormatSARIF:
		return r.generateSARIF(data)
	case FormatJUnit:
		return []byte(r.generateJUnit(data)), nil
	default:
		return json.MarshalIndent(data, "", "  ")
	}
}

func (r *Reporter) Write(data []byte, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}
	return os.WriteFile(abs, data, 0600)
}

func (r *Reporter) generateMarkdown(data *ScanData) string {
	var b strings.Builder
	b.WriteString("# XSS Scan Report\n\n")
	fmt.Fprintf(&b, "**Target:** %s\n\n", data.Target)
	fmt.Fprintf(&b, "**Scan Duration:** %dms\n\n", data.Duration)
	fmt.Fprintf(&b, "**Findings:** %d\n\n", len(data.Findings))

	if data.WAF != nil {
		b.WriteString("## WAF Detection\n\n")
		fmt.Fprintf(&b, "- **WAF:** %s\n", text.EscapeMarkdown(data.WAF.Name))
		status := "❌ Not bypassed"
		if data.WAF.Bypassed {
			status = "✅ Bypassed"
		}
		fmt.Fprintf(&b, "- **Bypass Status:** %s\n\n", status)
	}

	if len(data.Findings) == 0 {
		b.WriteString("✅ No vulnerabilities found.\n")
		return b.String()
	}

	b.WriteString("## Findings\n\n")
	for i, f := range data.Findings {
		fmt.Fprintf(&b, "### %d. [%s] %s\n\n", i+1, text.EscapeMarkdown(f.Severity), text.EscapeMarkdown(f.Description))
		fmt.Fprintf(&b, "- **Type:** %s\n", text.EscapeMarkdown(f.Type))
		fmt.Fprintf(&b, "- **URL:** %s\n", text.EscapeMarkdown(f.URL))
		fmt.Fprintf(&b, "- **Parameter:** %s\n", text.EscapeMarkdown(f.Parameter))
		fmt.Fprintf(&b, "- **Payload:** `%s`\n", text.EscapeMarkdown(f.Payload))
		if len(f.Payloads) > 1 {
			b.WriteString("- **Payload Variants:**\n")
			for _, v := range f.Payloads {
				fmt.Fprintf(&b, "  - `%s`\n", text.EscapeMarkdown(v))
			}
		}
		if len(f.CSPBypasses) > 0 {
			b.WriteString("- **CSP Bypasses:**\n")
			for _, cb := range f.CSPBypasses {
				fmt.Fprintf(&b, "  - **%s**: %s\n", text.EscapeMarkdown(cb.Type), text.EscapeMarkdown(cb.Description))
				fmt.Fprintf(&b, "    - Exploit: `%s`\n", text.EscapeMarkdown(cb.Exploit))
			}
		}
		pocURL := buildPOCURL(f.URL, f.Parameter, f.Payload, f.ParamType)
		if pocURL != "" {
			fmt.Fprintf(&b, "- **POC:** [%s](%s)\n", text.EscapeMarkdown(pocURL), pocURL)
		}
		fmt.Fprintf(&b, "- **Confidence:** %.0f%%\n", f.Confidence*100)
		fmt.Fprintf(&b, "- **Context:** %s\n\n", text.EscapeMarkdown(strings.Join(f.Contexts, ", ")))
		if curlCmd := buildCurlCommand(f.RawRequest, f.Scheme); curlCmd != "" {
			fmt.Fprintf(&b, "**Reproduce with curl:**\n\n```bash\n%s\n```\n\n", curlCmd)
		}
		if f.RawRequest != "" {
			fmt.Fprintf(&b, "<details><summary>Raw Request</summary>\n\n```http\n%s\n```\n\n</details>\n", text.EscapeMarkdown(f.RawRequest))
		}
		if f.RawResponse != "" {
			fmt.Fprintf(&b, "<details><summary>Raw Response</summary>\n\n```http\n%s\n```\n\n</details>\n", text.EscapeMarkdown(f.RawResponse))
		}
	}
	return b.String()
}

func (r *Reporter) generateHTML(data *ScanData) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>XSS Scan Report</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;background:#f5f5f5}
h1{color:#333;border-bottom:2px solid #e74c3c;padding-bottom:10px}
.finding{background:#fff;border-left:4px solid #e74c3c;padding:15px;margin:15px 0;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.finding h3{margin-top:0;color:#e74c3c}
.meta{color:#666;font-size:.9em}
.code{background:#f8f8f8;padding:8px;border-radius:3px;font-family:monospace;word-break:break-all;white-space:pre-wrap}
.severity-critical{color:#e74c3c;font-weight:bold}
.severity-high{color:#e67e22;font-weight:bold}
.severity-medium{color:#f39c12;font-weight:bold}
.severity-low{color:#3498db;font-weight:bold}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.8em;font-weight:600;margin-left:8px;vertical-align:middle}
.badge-verified{background:#27ae60;color:#fff}
.badge-partial{background:#f1c40f;color:#333}
.badge-structural{background:#e67e22;color:#fff}
.copy-btn{background:#eee;border:1px solid #ccc;border-radius:3px;padding:4px 10px;font-size:.85em;cursor:pointer;margin-left:8px;display:inline-block}
.copy-btn:hover{background:#ddd}
.copy-btn:active{background:#ccc}
details summary{cursor:pointer;color:#666;margin-top:8px}
</style>
</head>
<body>
`)
	fmt.Fprintf(&b, "<h1>XSS Scan Report</h1>\n")
	fmt.Fprintf(&b, "<p><strong>Target:</strong> %s<br>\n", html.EscapeString(data.Target))
	fmt.Fprintf(&b, "<strong>Duration:</strong> %dms<br>\n", data.Duration)
	fmt.Fprintf(&b, "<strong>Findings:</strong> %d</p>\n", len(data.Findings))

	if data.WAF != nil {
		b.WriteString("<div class=\"meta\" style=\"background:#fff3cd;padding:10px;border-radius:4px;margin:10px 0\">")
		b.WriteString(fmt.Sprintf("🛡️ WAF Detected: <strong>%s</strong>", html.EscapeString(data.WAF.Name)))
		if data.WAF.Bypassed {
			b.WriteString(" — <span style=\"color:green\">✅ Bypassed</span>")
		}
		b.WriteString("</div>\n")
	}

	if len(data.Findings) == 0 {
		b.WriteString("<p>✅ No vulnerabilities found.</p>\n")
	} else {
		for i, f := range data.Findings {
			// Escape all fields to prevent self-XSS in reports
			safeDesc := html.EscapeString(f.Description)
			safeType := html.EscapeString(f.Type)
			safeSev := html.EscapeString(f.Severity)
			safeURL := html.EscapeString(f.URL)
			safeParam := html.EscapeString(f.Parameter)
			safePayload := html.EscapeString(f.Payload)
			safeContexts := html.EscapeString(strings.Join(f.Contexts, ", "))

			// Build execution confidence badge
			var execBadge string
			if f.ExecutionVerified {
				execBadge = fmt.Sprintf(`<span class="badge badge-verified" title="Browser execution verified">✓ Browser Verified (%.0f%%)</span>`, f.ExecutionConfidence*100)
			} else if f.ExecutionConfidence > 0 {
				execBadge = `<span class="badge badge-partial" title="DOM mutation detected but not full execution">⚠ DOM Mutation Only</span>`
			} else {
				execBadge = `<span class="badge badge-structural" title="Structural analysis only — no runtime verification">⚠ Structural Only</span>`
			}

			fmt.Fprintf(&b, `<div class="finding">
<h3>%d. %s</h3>
<p class="meta">Type: %s | Severity: <span class="severity-%s">%s</span> | Confidence: %.0f%% %s</p>
<p><strong>URL:</strong> %s<br>
<strong>Parameter:</strong> %s<br>
<strong>Context:</strong> %s</p>
`, i+1, safeDesc, safeType, safeSev, safeSev, f.Confidence*100, execBadge, safeURL, safeParam, safeContexts)

			// CSP bypass badges + executable exploit payloads
			if len(f.CSPBypasses) > 0 {
				b.WriteString(`<div style="margin-top:8px;padding:8px;background:#fff3cd;border-radius:3px;font-size:.85em">`)
				b.WriteString(`<strong>🛡️ CSP Bypasses:</strong> `)
				for _, cb := range f.CSPBypasses {
					safeType := html.EscapeString(cb.Type)
					safeDesc := html.EscapeString(cb.Description)
					b.WriteString(fmt.Sprintf(`<span class="badge badge-partial" title="%s">%s</span> `, safeDesc, safeType))
				}
				b.WriteString(`</div>`)
				for _, cb := range f.CSPBypasses {
					if cb.Exploit == "" {
						continue
					}
					safeExploit := html.EscapeString(cb.Exploit)
					b.WriteString(fmt.Sprintf(`<div class="code" style="margin-top:4px">%s</div>`, safeExploit))
				}
			}

			fmt.Fprintf(&b, `<p><strong>Payload:</strong></p>
<div class="code">%s</div>
`, safePayload)

			// Aggregated variants (same param + context, multiple payloads)
			if len(f.Payloads) > 1 {
				b.WriteString(`<details><summary>Payload variants (` + fmt.Sprint(len(f.Payloads)) + `)</summary>` + "\n")
				for _, v := range f.Payloads {
					fmt.Fprintf(&b, `<div class="code" style="margin-top:4px">%s</div>`+"\n", html.EscapeString(v))
				}
				b.WriteString("</details>\n")
			}

			// CurlPOC section (pre-built curl command for query parameters)
			if f.CurlPOC != "" {
				safeCurlPOC := html.EscapeString(f.CurlPOC)
				fmt.Fprintf(&b, `<p><strong>Reproduce with curl:</strong></p>
<div class="code" id="curl-%d">%s</div>
<button class="copy-btn" data-curl="%s" onclick="copyToClipboard(this.getAttribute('data-curl'))">📋 Copy</button>`+"\n", i, safeCurlPOC, safeCurlPOC)
			}

			// Fallback: show raw-request-derived curl command if no CurlPOC
			if f.CurlPOC == "" {
				if curlCmd := buildCurlCommand(f.RawRequest, f.Scheme); curlCmd != "" {
					safeCurl := html.EscapeString(curlCmd)
					fmt.Fprintf(&b, `<p><strong>Reproduce with curl:</strong></p>
<div class="code" id="curl-%d">%s</div>
<button class="copy-btn" data-curl="%s" onclick="copyToClipboard(this.getAttribute('data-curl'))">📋 Copy</button>`+"\n", i, safeCurl, safeCurl)
				}
			}

			if pocURL := buildPOCURL(f.URL, f.Parameter, f.Payload, f.ParamType); pocURL != "" {
				safePOC := html.EscapeString(pocURL)
				fmt.Fprintf(&b, `<p><strong>POC:</strong> <a href="%s" target="_blank" rel="noopener">🔗 Open in browser</a></p>`+"\n", safePOC)
			}
			if f.RawRequest != "" {
				safeReq := html.EscapeString(f.RawRequest)
				fmt.Fprintf(&b, `<details><summary>Raw Request (paste into Burp Repeater)</summary>
<div class="code" id="raw-req-%d">%s</div>
<button class="copy-btn" data-req="%s" onclick="copyToClipboard(this.getAttribute('data-req'))">📋 Copy for Burp</button>
</details>`+"\n", i, safeReq, safeReq)
			}
			if f.RawResponse != "" {
				safeResp := html.EscapeString(f.RawResponse)
				fmt.Fprintf(&b, "<details><summary>Raw Response</summary><div class=\"code\">%s</div></details>\n", safeResp)
			}
			b.WriteString("</div>\n")
		}
	}
	b.WriteString(`<script>
function copyToClipboard(text) {
	if (navigator.clipboard && navigator.clipboard.writeText) {
		navigator.clipboard.writeText(text).then(function() {
			showCopied();
		}, function() {
			fallbackCopy(text);
		});
	} else {
		fallbackCopy(text);
	}
}
function fallbackCopy(text) {
	var ta = document.createElement('textarea');
	ta.value = text;
	ta.style.position = 'fixed';
	ta.style.opacity = '0';
	document.body.appendChild(ta);
	ta.select();
	try {
		document.execCommand('copy');
		showCopied();
	} catch (e) {
		alert('Copy failed — please select and copy manually');
	}
	document.body.removeChild(ta);
}
function showCopied() {
	var btns = document.querySelectorAll('.copy-btn');
	btns.forEach(function(btn) {
		if (btn.textContent !== '✅ Copied!') {
			btn.dataset.original = btn.textContent;
		}
	});
	var event = window.event;
	if (event && event.target) {
		var btn = event.target.closest('.copy-btn');
		if (btn) {
			var orig = btn.dataset.original || '📋 Copy';
			btn.textContent = '✅ Copied!';
			setTimeout(function() { btn.textContent = orig; }, 2000);
		}
	}
}
</script>
</body></html>`)
	return b.String()
}

// ScanData is the unified report data structure
type ScanData struct {
	Target   string
	Duration int64
	WAF      *model.WAFInfo
	Findings []FindingData
}

type FindingData struct {
	Type                string
	Severity            string
	Confidence          float64
	URL                 string
	Scheme              string // http or https, used for curl POC reconstruction
	Parameter           string
	ParamType           model.ParamType
	Payload             string
	Payloads            []string // aggregated variants (same param + context)
	Contexts            []string
	Description         string
	RawRequest          string
	RawResponse         string
	ExecutionVerified   bool    // true if browser execution verification passed
	ExecutionConfidence float64 // 0.0-1.0 confidence from browser verification
	CurlPOC             string  // pre-built curl command for this finding
	CSPBypasses         []model.CSPBypass
}

// FromScanResult converts a model.ScanResult to report.ScanData
func FromScanResult(result *model.ScanResult, durationMs int64) *ScanData {
	scanData := &ScanData{Target: result.Target, Duration: durationMs, WAF: result.Stats.WAF}
	for _, f := range result.Findings {
		// Extract scheme from the finding URL for accurate curl POC reconstruction
		scheme := "http"
		if u, err := url.Parse(f.URL); err == nil && u.Scheme != "" {
			scheme = u.Scheme
		}
		fd := FindingData{
			Type:                string(f.Type),
			Severity:            string(f.Severity),
			Confidence:          f.Confidence,
			URL:                 f.URL,
			Scheme:              scheme,
			Parameter:           f.Parameter,
			ParamType:           f.ParamType,
			Payload:             f.Payload,
			Payloads:            f.Payloads,
			Contexts:            f.Contexts,
			Description:         f.Description,
			RawRequest:          f.RawRequest,
			RawResponse:         f.RawResponse,
			ExecutionVerified:   f.ExecutionVerified,
			ExecutionConfidence: f.ExecutionConfidence,
			CSPBypasses:         f.CSPBypasses,
		}
		// Build curl POC for query parameters
		if f.ParamType == model.ParamQuery {
			fd.CurlPOC = buildCurlPOC(f.URL, f.Parameter, f.Payload, f.ParamType)
		}
		scanData.Findings = append(scanData.Findings, fd)
	}
	return scanData
}

// buildPOCURL constructs a clickable proof-of-concept URL by injecting
// the payload into the target parameter of the URL.
// For non-query parameters (body, header, cookie, path), it returns ""
// because a URL alone cannot reproduce the vulnerability — the raw HTTP
// request in the report serves as the POC instead.
func buildPOCURL(targetURL, param, payload string, paramType model.ParamType) string {
	if targetURL == "" || param == "" || payload == "" {
		return ""
	}
	if paramType != model.ParamQuery && paramType != "" {
		// Body/Header/Cookie/Path params cannot be reproduced via URL alone
		return ""
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// buildCurlPOC builds a curl command that reproduces the XSS finding.
// The payload is injected into the query parameter of the URL.
func buildCurlPOC(targetURL, param, payload string, paramType model.ParamType) string {
	if targetURL == "" || param == "" || payload == "" {
		return ""
	}
	if paramType != model.ParamQuery {
		return ""
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return "curl " + shellSingleQuote(u.String())
}

// shellSingleQuote escapes a string for safe use inside single quotes
// in a shell command. Single-quoted strings are literal in shell, except
// for single quotes themselves which must be: end-quote, escaped-quote, restart-quote.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// buildCurlCommand converts a raw HTTP request string into a reproducible
// curl command. The scheme parameter specifies the original URL scheme
// ("http" or "https") for accurate absolute URL reconstruction.
// Returns empty string if parsing fails.
func buildCurlCommand(rawReq, scheme string) string {
	if rawReq == "" {
		return ""
	}
	lines := strings.SplitN(rawReq, "\r\n", 2)
	if len(lines) < 1 {
		return ""
	}
	// Parse request line: "METHOD /path HTTP/1.1"
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return ""
	}
	method := parts[0]
	reqURL := parts[1]

	var b strings.Builder
	b.WriteString("curl -X ")
	b.WriteString(method)

	// Extract Host header for absolute URL reconstruction
	host := ""
	hasHost := false

	// Parse headers
	hasBody := false
	if len(lines) > 1 {
		bodyLines := strings.SplitN(lines[1], "\r\n\r\n", 2)
		for _, hdr := range strings.Split(bodyLines[0], "\r\n") {
			hdr = strings.TrimSpace(hdr)
			if hdr == "" {
				continue
			}
			lower := strings.ToLower(hdr)
			if strings.HasPrefix(lower, "host:") {
				host = strings.TrimSpace(hdr[5:])
				hasHost = true
			}
			// Skip headers curl adds automatically
			if strings.HasPrefix(lower, "content-length:") {
				hasBody = true
				continue
			}
			b.WriteString(" \\\n  -H ")
			b.WriteString(shellSingleQuote(hdr))
		}
		// Include body if present
		if hasBody && len(bodyLines) > 1 && bodyLines[1] != "" {
			b.WriteString(" \\\n  -d ")
			b.WriteString(shellSingleQuote(bodyLines[1]))
		}
	}

	// Build absolute URL: raw requests contain relative paths (/path?q=...).
	// curl requires absolute URLs. Reconstruct from Host header + request path.
	b.WriteString(" \\\n  ")
	if hasHost {
		b.WriteString(scheme)
		b.WriteString("://")
		b.WriteString(host)
	}
	b.WriteString(shellSingleQuote(reqURL))

	return b.String()
}
