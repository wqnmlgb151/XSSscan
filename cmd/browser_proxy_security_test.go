package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/test/testenv"
)

func TestBrowserVerificationUsesConfiguredProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	for _, mode := range []string{"plain", "authenticated", "direct", "rejected"} {
		t.Run(mode, func(t *testing.T) {
			var proxied atomic.Int64
			var leaked atomic.Int64
			target := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != "" {
					leaked.Add(1)
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, "<body>"+r.URL.Query().Get("q")+"</body>")
			}))
			defer target.Close()
			proxy := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode != "plain" && (r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy-user:browser-proxy-canary")) || (mode == "rejected" && r.Header.Get("Sec-Fetch-Mode") == "navigate")) {
					w.Header().Set("Proxy-Authenticate", `Basic realm="local proxy"`)
					w.WriteHeader(407)
					return
				}
				if !strings.HasPrefix(r.URL.String(), target.URL+"/") {
					w.WriteHeader(403)
					return
				}
				if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
					proxied.Add(1)
				}
				forward := r.Clone(r.Context())
				forward.RequestURI = ""
				forward.Header.Del("Proxy-Authorization")
				transport := &http.Transport{}
				defer transport.CloseIdleConnections()
				response, err := transport.RoundTrip(forward)
				if err != nil {
					w.WriteHeader(502)
					return
				}
				defer response.Body.Close()
				for name, values := range response.Header {
					w.Header()[name] = values
				}
				w.WriteHeader(response.StatusCode)
				io.Copy(w, response.Body)
			}))
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 30*time.Second)
			defer cancel()
			output := filepath.Join(t.TempDir(), "proxy.json")
			arguments := []string{"-test.run=^TestSecurityCLIProcess$", "--", "--url", target.URL + "/?q=x", "--proxy", proxy.URL, "--allow-private", "--types", "reflected", "--silent", "--max-payloads", "1", "--output", output}
			if mode != "plain" {
				arguments = append(arguments, "--proxy-username", "proxy-user", "--proxy-password", "browser-proxy-canary")
			}
			if mode == "direct" {
				arguments = append(arguments, "--browser-direct")
			}
			process := exec.CommandContext(ctx, os.Args[0], arguments...)
			var diagnostics bytes.Buffer
			process.Stderr = &diagnostics
			process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1")
			_ = process.Run()
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "rejected" && !strings.Contains(string(data), `"ExecutionVerified": true`) {
				t.Fatal("browser verification did not execute")
			}
			if mode != "direct" && mode != "rejected" && proxied.Load() == 0 {
				t.Fatal("Chrome bypassed configured proxy")
			}
			if mode == "rejected" && (!strings.Contains(string(data), "authentication rejected or unavailable") || strings.Contains(string(data), `"ExecutionVerified": true`)) {
				t.Fatal("proxy authentication rejection not reported as incomplete")
			}
			if mode == "direct" && (proxied.Load() != 0 || strings.Count(diagnostics.String(), "[WARNING]") != 1) {
				t.Fatal("direct bypass or warning semantics incorrect")
			}
			if leaked.Load() != 0 || strings.Contains(string(data), "browser-proxy-canary") || strings.Contains(diagnostics.String(), "browser-proxy-canary") {
				t.Fatal("proxy credentials leaked")
			}

		})
	}

}
