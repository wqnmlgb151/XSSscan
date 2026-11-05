package report

import (
	"reflect"
	"strings"
	"testing"
)

func TestShortCookiesPreserveReportSemantics(t *testing.T) {
	data := &ScanData{SchemaVersion: "1.1", Findings: []FindingData{{
		Payload: "<script>alert(1)</script>", Payloads: []string{"alert(1)"},
		Parameter: "content1", Description: "render content in element 1", Contexts: []string{"event_handler", "html_body"},
		RawRequest:  "GET / HTTP/1.1\r\nCookie: lang=en; x=1; session=1\r\nAuthorization: Bearer a\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\nSet-Cookie: session=1\r\n\r\n",
	}}}
	got, err := redactedCopy(data)
	if err != nil {
		t.Fatal(err)
	}
	want, actual := data.Findings[0], got.Findings[0]
	if actual.Payload != want.Payload || !reflect.DeepEqual(actual.Payloads, want.Payloads) || actual.Parameter != want.Parameter || actual.Description != want.Description || !reflect.DeepEqual(actual.Contexts, want.Contexts) {
		t.Fatalf("short cookie corrupted semantic fields: %+v", actual)
	}
	for _, format := range []OutputFormat{FormatJSON, FormatHTML, FormatMarkdown, FormatSARIF, FormatJUnit} {
		output, err := NewReporter().Generate(data, format)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"lang=en", "session=1", "Bearer a"} {
			if strings.Contains(string(output), secret) {
				t.Fatalf("%s leaked credential field", format)
			}
		}
	}
}

func TestCredentialEchoReplacementUsesBoundaries(t *testing.T) {
	const secret = "canary123456"
	data := &ScanData{Findings: []FindingData{{
		RawRequest: "GET / HTTP/1.1\r\nCookie: session=" + secret + "\r\n\r\n",
		Payload:    "alert('" + secret + "')", Parameter: secret,
		Description: "echo " + secret + "; prefix" + secret + "suffix / " + secret + " /",
	}}}
	got, err := redactedCopy(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Findings[0].Payload != data.Findings[0].Payload || got.Findings[0].Parameter != secret {
		t.Fatal("global replacement touched semantic fields")
	}
	if got.Findings[0].Description != "echo [REDACTED]; prefix"+secret+"suffix / [REDACTED] /" {
		t.Fatalf("boundary redaction: %s", got.Findings[0].Description)
	}
}

func TestShortCredentialsStillRedactAtPositions(t *testing.T) {
	for _, input := range []string{"http://u:p@local.test/?token=1", "password=1", `{"token":"1"}`, "Authorization: Bearer a"} {
		got := positionalText(input)
		if got == input {
			t.Errorf("credential position unchanged: %s", input)
		}
	}
}

func TestCredentialHeaderCopiesRedactWholeValues(t *testing.T) {
	for _, header := range []string{"Cookie: lang=en; x=1; session=1", "Set-Cookie: x=1; HttpOnly", `Authorization: Digest username="canary123456", response="canary654321"`} {
		data := &ScanData{Findings: []FindingData{{Description: header}}}
		got, err := redactedCopy(data)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(got.Findings[0].Description, ": [REDACTED]") {
			t.Errorf("header copy not fully redacted: %s", got.Findings[0].Description)
		}
		for _, format := range []OutputFormat{FormatJSON, FormatHTML, FormatMarkdown, FormatSARIF, FormatJUnit} {
			output, err := NewReporter().Generate(data, format)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"lang=en", "x=1", "session=1", "canary123456", "canary654321"} {
				if strings.Contains(string(output), secret) {
					t.Errorf("%s leaked header credential", format)
				}
			}
		}
	}
}
