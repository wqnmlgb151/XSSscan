package httpclient_test

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/report"
)

func TestProxyCredentialsStayAtProxy(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "HTTP"
		if secure {
			name = "HTTPS"
		}
		t.Run(name, func(t *testing.T) {
			var received, leaked atomic.Int64
			targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				if r.Header.Get("Proxy-Authorization") != "" {
					leaked.Add(1)
				}
				io.WriteString(w, "synthetic target")
			})
			var target *httptest.Server
			if secure {
				target = httptest.NewTLSServer(targetHandler)
			} else {
				target = httptest.NewServer(targetHandler)
			}
			defer target.Close()
			credentials := (&httpclient.ProxyConfig{Username: "proxy-user", Password: "proxy-password-canary"})
			expected, _ := credentials.ProxyAuthHeader()
			var authenticated atomic.Int64
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != expected {
					w.Header().Set("Proxy-Authenticate", `Basic realm="fixture"`)
					w.WriteHeader(http.StatusProxyAuthRequired)
					return
				}
				authenticated.Add(1)
				if r.Method == http.MethodConnect {
					// Only allow a connection to this test's own loopback target.
					if r.Host != strings.TrimPrefix(target.URL, "https://") {
						w.WriteHeader(403)
						return
					}
					upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
					if err != nil {
						t.Error(err)
						w.WriteHeader(502)
						return
					}
					defer upstream.Close()
					conn, buffered, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
					buffered.Flush()
					done := make(chan struct{})
					go func() { io.Copy(upstream, buffered); upstream.Close(); close(done) }()
					io.Copy(conn, upstream)
					conn.Close()
					<-done
					return
				}
				if r.URL.String() != target.URL+"/" {
					w.WriteHeader(403)
					return
				}
				forward := r.Clone(r.Context())
				forward.RequestURI = ""
				forward.Header.Del("Proxy-Authorization")
				transport := &http.Transport{}
				defer transport.CloseIdleConnections()
				response, err := transport.RoundTrip(forward)
				if err != nil {
					t.Error(err)
					w.WriteHeader(502)
					return
				}
				defer response.Body.Close()
				w.WriteHeader(response.StatusCode)
				io.Copy(w, response.Body)
			}))
			defer proxy.Close()
			transport := &http.Transport{}
			if secure {
				roots := x509.NewCertPool()
				roots.AddCert(target.Certificate())
				transport.TLSClientConfig = target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				transport.TLSClientConfig.InsecureSkipVerify = false
				transport.TLSClientConfig.RootCAs = roots
			}
			defer transport.CloseIdleConnections()
			credentials.URL = proxy.URL
			if err := credentials.ApplyToTransport(transport); err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			client = httpclient.WithCapture(client)
			ctx, capture := httpclient.RecordContext(context.Background())
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("proxy-authenticated request failed: %v", err)
			}
			defer response.Body.Close()
			io.Copy(io.Discard, response.Body)
			if response.StatusCode != 200 || authenticated.Load() != 1 || received.Load() != 1 || leaked.Load() != 0 {
				t.Fatalf("status=%d proxy=%d target=%d leaked=%d", response.StatusCode, authenticated.Load(), received.Load(), leaked.Load())
			}
			exchange := capture.Snapshot()
			if strings.Contains(exchange.Request, expected) || strings.Contains(exchange.Request, credentials.Password) {
				t.Fatal("proxy credential entered replay evidence")
			}
			for _, format := range []report.OutputFormat{report.FormatJSON, report.FormatHTML, report.FormatMarkdown, report.FormatSARIF, report.FormatJUnit} {
				data := &report.ScanData{SchemaVersion: "1.1", Status: model.ScanCompleted, Target: target.URL, Issues: []model.ScanIssue{{Stage: "fixture", HTTP: &exchange}}}
				body, err := report.NewReporter().Generate(data, format)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(body), credentials.Password) || strings.Contains(string(body), expected) {
					t.Fatal("proxy credential entered report")
				}
			}
		})
	}
}
