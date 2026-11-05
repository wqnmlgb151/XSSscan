package main

import (
	"context"
	"fmt"
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

func TestChromePinDNSRetainsSameOriginResources(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required")
	}
	var scripts atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/probe.js" {
			scripts.Add(1)
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, "window.fixtureLoaded=true;")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script src="/probe.js"></script><body>`+r.URL.Query().Get("q")+`</body>`)
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "pin.json")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecurityCLIProcess$", "--", "--url", strings.Replace(server.URL, "127.0.0.1", "localhost", 1)+"/?q=x", "--allow-private", "--chrome-pin-dns", "--types", "reflected", "--max-payloads", "1", "--silent", "--output", output)
	process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1")
	_ = process.Run()
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if scripts.Load() == 0 || !strings.Contains(string(data), `"ExecutionVerified": true`) {
		t.Fatalf("DNS pinning lost same-origin script or execution coverage (scripts=%d): %s", scripts.Load(), data)
	}
}
