package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"regexp"

	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/test/testenv"
)

func TestMarkerPrefixCLIUsesConfiguredProbes(t *testing.T) {
	var markers atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		if strings.Contains(value, "auditmarker") {
			markers.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<body>"+value+"</body>")
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "report.json")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecurityCLIProcess$", "--", "--url", server.URL+"/?q=x", "--allow-private", "--types", "reflected", "--verify-execution=false", "--marker-prefix", "auditmarker", "--probe", "--max-payloads", "1", "--silent", "--output", output)
	process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1")
	_ = process.Run()
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if markers.Load() == 0 || !strings.Contains(string(data), "reflected_xss") {
		t.Fatal("custom marker/probes lost reflected detection")
	}
}

func TestRandomMarkerPrefixIsStableWithinRun(t *testing.T) {
	var previous string
	for run := 0; run < 2; run++ {
		var mu sync.Mutex
		prefixes := map[string]bool{}
		pattern := regexp.MustCompile(`[a-z]{10}[a-z0-9]{12}`)
		server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			value := r.URL.Query().Get("q")
			mu.Lock()
			for _, marker := range pattern.FindAllString(value, -1) {
				prefixes[marker[:10]] = true
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<body>"+value+"</body>")
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecurityCLIProcess$", "--", "--url", server.URL+"/?q=x", "--allow-private", "--types", "reflected", "--verify-execution=false", "--random-marker-prefix", "--max-payloads", "1", "--silent")
		process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1")
		_ = process.Run()
		cancel()
		server.Close()
		mu.Lock()
		if len(prefixes) != 1 {
			t.Fatalf("per-run prefixes: %v", prefixes)
		}
		for prefix := range prefixes {
			if prefix == previous {
				t.Fatal("prefix reused across runs")
			}
			previous = prefix
		}
		mu.Unlock()
	}
}
