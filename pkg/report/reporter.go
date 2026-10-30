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
	if data == nil {
		return nil, fmt.Errorf("report data is nil")
	}
	copy := *data
	copy.Issues = append([]model.ScanIssue(nil), data.Issues...)
	if len(data.Coverage) == 0 {
		for _, module := range data.Modules {
			copy.Coverage = append(copy.Coverage, module.Coverage...)
		}
	}
	for _, module := range data.Modules {
		for _, issue := range module.Issues {
			present := false
			for _, existing := range copy.Issues {
				present = present || (existing.Target == issue.Target && existing.Stage == issue.Stage && existing.Message == issue.Message)
			}
			if !present {
				copy.Issues = append(copy.Issues, issue)
			}
		}
	}
	if copy.Errors == 0 {
		copy.Errors = len(copy.Issues)
	}
	copy.Status = model.ResolveStatus(data.Status, data.Modules, copy.Issues, copy.Errors)
	data = &copy
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
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

func (r *Reporter) Write(data []byte, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(abs), ".xsscan-report-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, abs)
}

func (r *Reporter) generateMarkdown(data *ScanData) string {
	var b strings.Builder
	b.WriteString("# XSS Scan Report\n\n")
	fmt.Fprintf(&b, "**Target:** %s\n\n", data.Target)
	fmt.Fprintf(&b, "**Scan Duration:** %dms\n\n", data.Duration)
	fmt.Fprintf(&b, "**Findings:** %d\n\n", len(data.Findings))

	fmt.Fprintf(&b, "**Status:** %s\n\n", reportStatus(data))
	fmt.Fprintf(&b, "**Requests:** %d | **Payloads:** %d | **Errors:** %d\n\n", data.RequestsSent, data.PayloadsSent, data.Errors)
	for _, coverage := range data.Coverage {
		fmt.Fprintf(&b, "- Coverage: %s\n", text.EscapeMarkdown(coverage.String()))
	}
	for _, observation := range data.CrossModule {
		fmt.Fprintf(&b, "\n- Observation: %s / %s / %s: %s\n", text.EscapeMarkdown(observation.Module), text.EscapeMarkdown(string(observation.Kind)), text.EscapeMarkdown(observation.Subject), text.EscapeMarkdown(observation.Detail))
	}
	b.WriteString("\n")
	if len(data.Modules) > 0 {
		b.WriteString("| Type | Target | Status | Requests | Candidates | Findings | Reason |\n| --- | --- | --- | --- | --- | --- | --- |\n")
		for _, module := range data.Modules {
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %d | %d | %s |\n", text.EscapeMarkdown(module.Type), text.EscapeMarkdown(module.Target), module.Status, module.Requests, module.Candidates, module.Findings, text.EscapeMarkdown(module.Reason))
		}
		b.WriteString("\n")
	}
	for _, issue := range data.Issues {
		fmt.Fprintf(&b, "- %s / %s: %s\n", text.EscapeMarkdown(issue.Target), text.EscapeMarkdown(issue.Stage), text.EscapeMarkdown(issue.Message))
		if issue.HTTP != nil {
			fmt.Fprintf(&b, "\n%s\n", httpFence(issue.HTTP.Request+"\n"+issue.HTTP.Response))
		}
	}
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
		if reportStatus(data) == model.ScanCompleted {
			b.WriteString("✅ No vulnerabilities found.\n")
		} else {
			b.WriteString("Scan incomplete; no findings recorded.\n")
		}
		return b.String()
	}

	b.WriteString("## Findings\n\n")
	for i, f := range data.Findings {
		fmt.Fprintf(&b, "### %d. [%s] %s\n\n", i+1, text.EscapeMarkdown(f.Severity), text.EscapeMarkdown(f.Description))
		fmt.Fprintf(&b, "- **Type:** %s\n", text.EscapeMarkdown(f.Type))
		fmt.Fprintf(&b, "- **URL:** %s\n", text.EscapeMarkdown(f.URL))
		fmt.Fprintf(&b, "- **Parameter:** %s\n", text.EscapeMarkdown(f.Parameter))
		fmt.Fprintf(&b, "- **Payload:** `%s`\n", text.EscapeMarkdown(f.Payload))
		for _, field := range evidenceFields(f.Evidence) {
			if field[0] == "Trigger Request" || field[0] == "Submission Response" || field[0] == "Initial Request" {
				fmt.Fprintf(&b, "\n**%s:**\n\n%s\n", field[0], httpFence(field[1]))
			} else {
				fmt.Fprintf(&b, "- **%s:** `%s`\n", field[0], text.EscapeMarkdown(field[1]))
			}
		}
		// Variants exclude the primary payload — it is printed above.
		hasVariants := false
		for _, v := range f.Payloads {
			if v != f.Payload {
				hasVariants = true
				break
			}
		}
		if hasVariants {
			b.WriteString("- **Payload Variants:**\n")
			for _, v := range f.Payloads {
				if v != f.Payload {
					fmt.Fprintf(&b, "  - `%s`\n", text.EscapeMarkdown(v))
				}
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
		if curlCmd := findingCurl(f); curlCmd != "" {
			fmt.Fprintf(&b, "**Reproduce with curl:**\n\n```bash\n%s\n```\n\n", curlCmd)
		}
		if f.RawRequest != "" {
			fmt.Fprintf(&b, "<details><summary>Raw Request</summary>\n\n%s\n</details>\n", httpFence(f.RawRequest))
		}
		if f.RawResponse != "" {
			fmt.Fprintf(&b, "<details><summary>Raw Response</summary>\n\n%s\n</details>\n", httpFence(f.RawResponse))
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

	fmt.Fprintf(&b, "<p><strong>Status:</strong> %s</p>\n", html.EscapeString(string(reportStatus(data))))
	fmt.Fprintf(&b, "<p>Requests: %d | Payloads: %d | Errors: %d</p>\n", data.RequestsSent, data.PayloadsSent, data.Errors)
	for _, coverage := range data.Coverage {
		fmt.Fprintf(&b, "<p>Coverage: %s</p>\n", html.EscapeString(coverage.String()))
	}
	for _, observation := range data.CrossModule {
		fmt.Fprintf(&b, "<p>Observation: %s / %s / %s: %s</p>\n", html.EscapeString(observation.Module), html.EscapeString(string(observation.Kind)), html.EscapeString(observation.Subject), html.EscapeString(observation.Detail))
	}
	for _, module := range data.Modules {
		fmt.Fprintf(&b, "<p>Module: %s / %s / %s — %s | Requests: %d | Candidates: %d | Findings: %d</p>\n", html.EscapeString(module.Type), html.EscapeString(module.Target), html.EscapeString(string(module.Status)), html.EscapeString(module.Reason), module.Requests, module.Candidates, module.Findings)
	}
	for _, issue := range data.Issues {
		fmt.Fprintf(&b, "<p>%s / %s: %s</p>\n", html.EscapeString(issue.Target), html.EscapeString(issue.Stage), html.EscapeString(issue.Message))
		if issue.HTTP != nil {
			fmt.Fprintf(&b, "<pre>%s\n%s</pre>", html.EscapeString(issue.HTTP.Request), html.EscapeString(issue.HTTP.Response))
		}
	}
	if data.WAF != nil {
		b.WriteString("<div class=\"meta\" style=\"background:#fff3cd;padding:10px;border-radius:4px;margin:10px 0\">")
		b.WriteString(fmt.Sprintf("🛡️ WAF Detected: <strong>%s</strong>", html.EscapeString(data.WAF.Name)))
		if data.WAF.Bypassed {
			b.WriteString(" — <span style=\"color:green\">✅ Bypassed</span>")
		}
		b.WriteString("</div>\n")
	}

	if len(data.Findings) == 0 {
		if reportStatus(data) == model.ScanCompleted {
			b.WriteString("<p>✅ No vulnerabilities found.</p>\n")
		} else {
			b.WriteString("<p>Scan incomplete; no findings recorded.</p>\n")
		}
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
			} else if f.Evidence.VerificationError != "" {
				execBadge = `<span class="badge badge-partial">⚠ Execution Verification Incomplete</span>`
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
			for _, field := range evidenceFields(f.Evidence) {
				fmt.Fprintf(&b, "<p><strong>%s:</strong></p><div class=\"code\">%s</div>\n", html.EscapeString(field[0]), html.EscapeString(field[1]))
			}

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

			// Aggregated variants excluding the primary payload (printed above)
			variantCount := 0
			for _, v := range f.Payloads {
				if v != f.Payload {
					variantCount++
				}
			}
			if variantCount > 0 {
				b.WriteString(`<details><summary>Payload variants (` + fmt.Sprint(variantCount) + `)</summary>` + "\n")
				for _, v := range f.Payloads {
					if v != f.Payload {
						fmt.Fprintf(&b, `<div class="code" style="margin-top:4px">%s</div>`+"\n", html.EscapeString(v))
					}
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
				if curlCmd := findingCurl(f); curlCmd != "" {
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
</details>`+"\n", i, safeReq, strings.ReplaceAll(strings.ReplaceAll(safeReq, "\r", "&#13;"), "\n", "&#10;"))
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
	Coverage      []model.CheckCoverage `json:"coverage,omitempty"`
	SchemaVersion string
	Modules       []model.ModuleResult
	Status        model.ScanStatus
	Issues        []model.ScanIssue
	RequestsSent  int
	PayloadsSent  int
	Errors        int
	Target        string
	Duration      int64
	WAF           *model.WAFInfo
	// CrossModule carries the leads the modules produced for each other. It is reported
	// so a reader can see what each module observed beyond its own verdict; it contains
	// no conclusion about the target, by construction.
	CrossModule []model.CrossModuleObservation `json:"cross_module,omitempty"`
	Findings    []FindingData
}

type FindingData struct {
	Evidence   model.Evidence
	Type       string
	Severity   string
	Confidence float64
	URL        string
	Scheme     string // http or https, used for curl POC reconstruction
	Parameter  string
	ParamType  model.ParamType
	// ReflectionPath scopes this finding to one reflection position. It is
	// recorded so a reviewer can tell whether two findings share an execution
	// proof or were verified independently. Omitted when analysis could not
	// anchor the position.
	ReflectionPath      string
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

// evidenceFields keeps candidate provenance visible in human-readable reports.
func evidenceFields(e model.Evidence) [][2]string {
	all := [][2]string{{"Analysis Method", e.AnalysisMethod}, {"Parse Error", e.ParseError}, {"Detection Method", e.DetectionMethod}, {"Trigger URL", e.TriggerURL}, {"Verification Payload", e.VerificationPayload}, {"Verification Error", e.VerificationError}, {"Dialog Message", e.DialogMessage}, {"Interaction", e.Interaction}}
	for _, diagnostic := range e.Diagnostics {
		all = append(all, [2]string{"Browser Diagnostic", diagnostic})
	}
	for _, flow := range e.DataFlow {
		all = append(all, [2]string{"Data Flow (static hypothesis)", fmt.Sprintf("%s[%q] -> %s; script #%d; source bytes [%d,%d); sink bytes [%d,%d)", flow.Source, flow.Key, flow.Sink, flow.ScriptIndex, flow.SourceStart, flow.SourceEnd, flow.SinkStart, flow.SinkEnd)})
	}
	if e.HTTP != nil {
		all = append(all, [2]string{"Initial Request", e.HTTP.InitialRequest}, [2]string{"Initial Request Base64", e.HTTP.InitialRequestBase64})
		all = append(all, [2]string{"Request Base64", e.HTTP.RequestBase64}, [2]string{"Response Base64", e.HTTP.ResponseBase64})
		all = append(all, [2]string{"HTTP Body Limits", fmt.Sprintf("request_truncated=%t; response_truncated=%t; response_incomplete=%t", e.HTTP.RequestTruncated, e.HTTP.ResponseTruncated, e.HTTP.ResponseIncomplete)})
		if e.SubmissionHTTP != nil {
			all = append(all, [2]string{"Trigger Request", e.HTTP.Request}, [2]string{"Submission Response", e.SubmissionHTTP.Response})
			all = append(all, [2]string{"Submission Request Base64", e.SubmissionHTTP.RequestBase64}, [2]string{"Submission Response Base64", e.SubmissionHTTP.ResponseBase64})
		}
	}

	var fields [][2]string
	for _, field := range all {
		if field[1] != "" {
			fields = append(fields, field)
		}
	}
	return fields
}

// FromScanResult converts a model.ScanResult to report.ScanData
func FromScanResult(result *model.ScanResult, durationMs int64) *ScanData {
	scanData := &ScanData{SchemaVersion: "1.1", Coverage: append([]model.CheckCoverage(nil), result.Stats.Coverage...), Modules: result.Stats.Modules, Target: result.Target, Duration: durationMs, WAF: result.Stats.WAF, Status: result.Stats.Status, Issues: result.Stats.Issues, RequestsSent: result.Stats.RequestsSent, PayloadsSent: result.Stats.PayloadsSent, Errors: result.Stats.Errors, CrossModule: result.Stats.CrossModule.Sorted()}
	for _, f := range result.Findings {
		// Extract scheme from the finding URL for accurate curl POC reconstruction
		scheme := "http"
		if u, err := url.Parse(f.URL); err == nil && u.Scheme != "" {
			scheme = u.Scheme
		}
		fd := FindingData{
			Evidence:            f.Evidence,
			Type:                string(f.Type),
			Severity:            string(f.Severity),
			Confidence:          f.Confidence,
			URL:                 f.URL,
			Scheme:              scheme,
			Parameter:           f.Parameter,
			ParamType:           f.ParamType,
			ReflectionPath:      f.ReflectionPath,
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
		// Prefer the captured request so authentication and CSRF remain reproducible.
		fd.CurlPOC = findingCurl(fd)
		if fd.CurlPOC == "" && f.ParamType == model.ParamQuery && f.RawRequest == "" {
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
				continue
			}
			b.WriteString(" \\\n  -H ")
			b.WriteString(shellSingleQuote(hdr))
		}
		// Include body if present
		if len(bodyLines) > 1 && bodyLines[1] != "" {
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

func reportStatus(data *ScanData) model.ScanStatus {
	return model.ResolveStatus(data.Status, data.Modules, data.Issues, data.Errors)
}

func httpFence(raw string) string {
	longest, run := 0, 0
	for _, char := range raw {
		if char == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + "http\n" + raw + "\n" + fence + "\n"
}

func findingCurl(f FindingData) string {
	if f.Evidence.HTTP != nil && (f.Evidence.HTTP.RequestTruncated || f.Evidence.HTTP.InitialRequestTruncated) {
		return ""
	}
	return buildCurlCommand(f.RawRequest, f.Scheme)
}
