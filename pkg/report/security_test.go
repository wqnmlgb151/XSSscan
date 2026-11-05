package report

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"strings"
	"sync"
	"testing"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func securityFixture() (*ScanData, []string) {
	secrets := []string{"bearer-canary-123", "cookie-canary-234", "response-canary-345", "query-canary-456", "body-canary-567", "html-canary-678", "user-canary-789"}
	raw := "POST /?access_token=" + secrets[3] + " HTTP/1.1\r\nHost: local.test\r\nAuthorization: Bearer " + secrets[0] + "\r\nCookie: session=" + secrets[1] + "\r\nContent-Type: application/json\r\n\r\n{\"password\":\"" + secrets[4] + "\",\"q\":\"hello\"}"
	response := "HTTP/1.1 200 OK\r\nSet-Cookie: session=" + secrets[2] + "; HttpOnly\r\n\r\n<input type=hidden name=csrf_token value='" + secrets[5] + "'>"
	e := &model.HTTPExchange{URL: "http://" + secrets[6] + ":" + secrets[4] + "@local.test/?token=" + secrets[3], InitialURL: "http://local.test/?token=" + secrets[3], InitialRequest: raw, Request: raw, Response: response, RequestBase64: base64.StdEncoding.EncodeToString([]byte(raw)), ResponseBase64: base64.StdEncoding.EncodeToString([]byte(response)), InitialRequestBase64: base64.StdEncoding.EncodeToString([]byte(raw))}
	issue := model.ScanIssue{Target: e.URL, Message: "echo " + strings.Join(secrets, " "), HTTP: e}
	data := &ScanData{SchemaVersion: "1.1", Target: e.URL, Issues: []model.ScanIssue{issue}, Modules: []model.ModuleResult{{Type: "reflected", Target: e.URL, Status: model.ScanPartial, Issues: []model.ScanIssue{issue}}}, Findings: []FindingData{{Type: "reflected_xss", Severity: "high", URL: e.URL, Parameter: "q", ParamType: model.ParamQuery, Payload: "<script>alert(1)</script>", RawRequest: raw, RawResponse: response, CurlPOC: "curl -H 'Authorization: Bearer " + secrets[0] + "' '" + e.URL + "'", Evidence: model.Evidence{HTTP: e, SubmissionHTTP: e, Reflection: response, Context: secrets[4], Diagnostics: []string{issue.Message}, ScreenshotPath: "/private/" + secrets[1] + ".png"}}}}
	return data, secrets
}

func TestDefaultReportsRedactCredentialsAcrossAllFormats(t *testing.T) {
	data, secrets := securityFixture()
	before, _ := json.Marshal(data)
	for _, format := range []OutputFormat{FormatJSON, FormatHTML, FormatMarkdown, FormatSARIF, FormatJUnit} {
		t.Run(string(format), func(t *testing.T) {
			body, err := NewReporter().Generate(data, format)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range secrets {
				if strings.Contains(string(body), secret) || strings.Contains(string(body), base64.StdEncoding.EncodeToString([]byte(secret))) {
					t.Fatalf("%s leaked a synthetic credential", format)
				}
			}
			if strings.Contains(string(body), data.Findings[0].Evidence.HTTP.RequestBase64) {
				t.Fatal("raw base64 leaked")
			}
			if !strings.Contains(string(body), "REDACTED") {
				t.Fatal("missing redaction marker")
			}
			if format == FormatJSON || format == FormatSARIF {
				var parsed any
				if err := json.Unmarshal(body, &parsed); err != nil {
					t.Fatal(err)
				}
			}
			if format == FormatJUnit {
				var parsed anyXML
				if err := xml.Unmarshal(body, &parsed); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	after, _ := json.Marshal(data)
	if string(before) != string(after) {
		t.Fatal("report redaction mutated scanning evidence")
	}
}

func TestRedactionPreservesSchemaEnumsAndLargeCounters(t *testing.T) {
	for _, secret := range []string{"1", "completed", "high", "reflected_xss"} {
		data := &ScanData{SchemaVersion: "1.1", Status: model.ScanCompleted, Duration: 9007199254740993,
			Findings: []FindingData{{Type: "reflected_xss", Severity: "high", ParamType: model.ParamQuery, RawRequest: "GET / HTTP/1.1\r\nCookie: session=" + secret + "\r\n\r\n"}}}
		body, err := NewReporter().Generate(data, FormatJSON)
		if err != nil {
			t.Fatal(err)
		}
		var got ScanData
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got.SchemaVersion != "1.1" || got.Status != model.ScanCompleted || got.Duration != data.Duration || got.Findings[0].Severity != "high" || got.Findings[0].Type != "reflected_xss" || got.Findings[0].ParamType != model.ParamQuery {
			t.Fatalf("schema/enum changed for short credential: %s", body)
		}
	}
}

func TestCredentialCopiesInEveryReport(t *testing.T) {
	for _, tc := range []struct{ name, request, secret string }{
		{"custom-auth-header", "GET / HTTP/1.1\r\nHost: local\r\nX-Auth-Key: header-opaque-canary\r\n\r\n", "header-opaque-canary"},
		{"lf-custom-header", "GET / HTTP/1.1\nHost: local\nX-Opaque: lf-header-canary\n\n", "lf-header-canary"},
		{"uppercase-url", "GET HTTP://local.test/?%74oken=scheme-canary HTTP/1.1\r\nHost: local\r\n\r\n", "scheme-canary"},
		{"basic-auth", "GET / HTTP/1.1\r\nHost: local\r\nAuthorization: Basic " + base64.StdEncoding.EncodeToString([]byte("worker:basic-password-canary")) + "\r\n\r\n", "basic-password-canary"},
		{"multipart", "POST / HTTP/1.1\r\nHost: local\r\nContent-Type: multipart/form-data; boundary=fixture\r\n\r\n--fixture\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nmultipart-canary\r\n--fixture--\r\n", "multipart-canary"},
		{"escaped-json", "POST / HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\n\r\n{\"password\":\"escaped-\\u0063anary\"}", "escaped-canary"},
		{"encoded-form", "POST / HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npassword=form%2Bcanary%26end", "form+canary&end"},
		{"relative-location", "HTTP/1.1 302 Found\r\nLocation: /callback?code=redirect-canary\r\n\r\n", "redirect-canary"},
		{"protocol-location", "HTTP/1.1 302 Found\r\nLocation: //worker:redirect-password@local.test/callback?token=other\r\n\r\n", "redirect-password"},
	} {
		for _, format := range []OutputFormat{FormatJSON, FormatHTML, FormatMarkdown, FormatSARIF, FormatJUnit} {
			t.Run(tc.name+"/"+string(format), func(t *testing.T) {
				data := &ScanData{Issues: []model.ScanIssue{{Message: "diagnostic echo " + tc.secret}}, Findings: []FindingData{{RawRequest: tc.request, Description: "echo " + tc.secret, Evidence: model.Evidence{Reflection: tc.secret}}}}
				output, err := NewReporter().Generate(data, format)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(output), tc.secret) {
					t.Fatalf("credential copy leaked: %s/%s", tc.name, format)
				}
			})
		}
	}
}

func TestPrebuiltCurlDoesNotBypassSafeReports(t *testing.T) {
	for _, format := range []OutputFormat{FormatJSON, FormatHTML, FormatMarkdown, FormatSARIF, FormatJUnit} {
		data := &ScanData{Findings: []FindingData{{URL: "http://local.test/?q=x", Parameter: "q", ParamType: model.ParamQuery, Payload: "<script>alert(1)</script>", CurlPOC: "curl -H 'X-Unknown-Auth: curl-only-canary' http://local.test/"}}}
		body, err := NewReporter().Generate(data, format)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "curl-only-canary") {
			t.Fatalf("prebuilt curl leaked in %s", format)
		}
	}
}

func TestConcurrentSafeAndRawReportsKeepPoliciesSeparate(t *testing.T) {
	data, _ := securityFixture()
	safe, raw := NewReporter(), NewReporterWithOptions(Options{IncludeRawEvidence: true})
	var group sync.WaitGroup
	for _, format := range []OutputFormat{FormatJSON, FormatHTML, FormatMarkdown, FormatSARIF, FormatJUnit} {
		group.Go(func() {
			body, err := safe.Generate(data, format)
			if err != nil || strings.Contains(string(body), "bearer-canary-123") {
				t.Errorf("safe policy changed: %v", err)
			}
		})
		group.Go(func() {
			body, err := raw.Generate(data, format)
			if err != nil || !strings.Contains(string(body), "bearer-canary-123") {
				t.Errorf("raw policy changed: %v", err)
			}
		})
	}
	group.Wait()
}
