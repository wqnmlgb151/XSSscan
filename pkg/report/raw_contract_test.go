package report

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"golang.org/x/net/html"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestJUnitBinaryEvidenceRemainsParseable(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n\r\n" + string([]byte{0, 1, 255})
	e := model.HTTPExchange{Response: raw, ResponseBase64: base64.StdEncoding.EncodeToString([]byte(raw))}
	data := FromScanResult(&model.ScanResult{Findings: []model.Finding{{RawResponse: raw, Payload: "nul\x00", Evidence: model.Evidence{HTTP: &e}}}}, 0)
	out, err := NewReporterWithOptions(Options{IncludeRawEvidence: true}).Generate(data, FormatJUnit)
	if err != nil {
		t.Fatal(err)
	}
	var parsed anyXML
	if err := xml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	if !strings.Contains(string(out), e.ResponseBase64) {
		t.Fatal("binary bytes lost")
	}
}

type anyXML struct {
	XMLName xml.Name
	Inner   string `xml:",innerxml"`
}

func TestOriginalHTTPAcrossFiveFormatsAndHTMLCopy(t *testing.T) {
	raw := "POST /a%2Fb?q=original HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer raw-secret\r\nCookie: session=original\r\nContent-Length: 15\r\n\r\nq=<script>&x='`"
	response := "HTTP/1.1 200 OK\r\nSet-Cookie: session=response-secret\r\n\r\noriginal response"
	data := FromScanResult(&model.ScanResult{Findings: []model.Finding{{URL: "http://local", ParamType: model.ParamBody, RawRequest: raw, RawResponse: response, Evidence: model.Evidence{HTTP: &model.HTTPExchange{Request: raw, Response: response}}}}}, 0)
	for _, format := range []OutputFormat{FormatJSON, FormatHTML, FormatMarkdown, FormatSARIF, FormatJUnit} {
		out, err := NewReporterWithOptions(Options{IncludeRawEvidence: true}).Generate(data, format)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "raw-secret") || !strings.Contains(string(out), "response-secret") || strings.Contains(string(out), "REDACTED") {
			t.Fatalf("%s lost evidence", format)
		}
		switch format {
		case FormatJSON:
			var decoded ScanData
			if err := json.Unmarshal(out, &decoded); err != nil || decoded.Findings[0].RawRequest != raw {
				t.Fatalf("JSON altered evidence: %v", err)
			}
		case FormatHTML:
			tokenizer := html.NewTokenizer(strings.NewReader(string(out)))
			found := false
			for tokenizer.Next() != html.ErrorToken {
				token := tokenizer.Token()
				for _, attr := range token.Attr {
					if attr.Key == "data-req" {
						found = true
						if attr.Val != raw {
							t.Fatalf("HTML copy changed raw bytes: %q", attr.Val)
						}
					}
				}
			}
			if !found {
				t.Fatal("copy attribute missing")
			}
		case FormatMarkdown:
			if !strings.Contains(string(out), raw) {
				t.Fatal("Markdown mutated request")
			}
		case FormatSARIF:
			var decoded sarifReport
			if err := json.Unmarshal(out, &decoded); err != nil || decoded.Runs[0].Results[0].Properties.RawRequest != raw {
				t.Fatalf("SARIF altered request: %v", err)
			}
		case FormatJUnit:
			var decoded struct {
				Suite struct {
					Case []struct {
						Failure string `xml:"failure"`
					} `xml:"testcase"`
				} `xml:"testsuite"`
			}
			if err := xml.Unmarshal(out, &decoded); err != nil || !strings.Contains(decoded.Suite.Case[0].Failure, raw) {
				t.Fatalf("JUnit altered request: %v", err)
			}
		}
	}
}

func TestAtomicReportReplacementAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := NewReporter().Write([]byte("new"), path); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "new" {
		t.Fatal("report replacement failed")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("permissions %o", info.Mode().Perm())
		}
	} else {
		t.Log("POSIX 0600 enforcement needs Unix runtime; Windows checked replacement only")
	}
	if err := NewReporter().Write([]byte("bad"), dir); err == nil {
		t.Fatal("accepted directory output")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary artifact leaked: %+v", entries)
	}
}
