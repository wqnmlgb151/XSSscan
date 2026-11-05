package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xsscan/xsscan/test/testenv"
)

func TestCredentialSourcesAndArgvWarning(t *testing.T) {
	for _, mode := range []string{"env", "cli", "file", "silent"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var seen []string
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen = append(seen, r.Header.Get("Authorization"))
				mu.Unlock()
				fmt.Fprint(w, "<body>safe</body>")
			}))
			defer server.Close()
			dir := t.TempDir()
			config := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(config, []byte("jwt: yaml-canary\n"), 0600); err != nil {
				t.Fatal(err)
			}
			tokenFile := filepath.Join(dir, "token")
			if err := os.WriteFile(tokenFile, []byte("file-canary\r\n"), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-test.run=^TestSecurityCLIProcess$", "--", "--url", server.URL + "/?q=x", "--config", config, "--allow-private", "--types", "reflected", "--verify-execution=false", "--max-payloads", "1"}
			want := "env-canary"
			if mode == "cli" || mode == "silent" {
				args = append(args, "--jwt", "cli-canary")
				want = "cli-canary"
			}
			if mode == "file" {
				args = append(args, "--jwt-file", tokenFile)
				want = "file-canary"
			}
			if mode == "silent" {
				args = append(args, "--silent")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			process := exec.CommandContext(ctx, os.Args[0], args...)
			process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1", "XSSCAN_JWT=env-canary")
			var stderr bytes.Buffer
			process.Stderr = &stderr
			_ = process.Run()
			mu.Lock()
			defer mu.Unlock()
			if len(seen) == 0 {
				t.Fatalf("no local request; %s", stderr.String())
			}
			if seen[0] != "Bearer "+want {
				t.Fatalf("credential precedence got %q want %q", seen[0], want)
			}
			if mode == "cli" && !strings.Contains(stderr.String(), "process") {
				t.Fatal("argv credential warning missing")
			}
			if mode == "silent" && stderr.Len() != 0 {
				t.Fatalf("silent emitted warning: %s", stderr.String())
			}
		})
	}
}
