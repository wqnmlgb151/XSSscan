package main

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Separate CLI processes exercise --allow-private without changing the test
// process's package-global scanner configuration or SSRF state.
func TestSecurityCLIProcess(t *testing.T) {
	if os.Getenv("XSSCAN_SECURITY_CLI_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			rootCmd.SetArgs(os.Args[i+1:])
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing CLI arguments")
}

func TestAuthenticatedAutomaticFormsAreNotSubmitted(t *testing.T) {
	var submitted atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			submitted.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body><form method="post" action="/save"><input name="message"><input type="hidden" name="csrf" value="synthetic-csrf"></form></body>`)
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "report.json")
	process := exec.Command(os.Args[0], "-test.run=^TestSecurityCLIProcess$", "--", "--url", server.URL, "--allow-private", "--types", "reflected", "--verify-execution=false", "--header", "Authorization: Bearer synthetic-auth", "--silent", "--max-payloads", "1", "--output", output)
	process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1")
	_ = process.Run() // A policy skip may deliberately return the incomplete exit code.
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("no report: %v", err)
	}
	if submitted.Load() != 0 {
		t.Fatalf("authenticated automatic POST form submitted %d times", submitted.Load())
	}
	data, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(data), "authenticated automatic POST form skipped") {
		t.Fatal("skip reason missing from report")
	}
	optIn := exec.Command(os.Args[0], append(process.Args[1:], "--allow-form-submit")...)
	optIn.Env = process.Env
	_ = optIn.Run()
	if submitted.Load() == 0 {
		t.Fatal("explicit form submission opt-in ignored")
	}
	submitted.Store(0)
	noForms := exec.Command(os.Args[0], append(process.Args[1:], "--allow-form-submit", "--no-forms")...)
	noForms.Env = process.Env
	_ = noForms.Run()
	if submitted.Load() != 0 {
		t.Fatal("no-forms ignored")
	}
}

func TestDiscoveryScopeAndPasswordFormsDoNotReachTargets(t *testing.T) {
	var forbidden atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logout" || r.URL.Path == "/excluded" || r.URL.Path == "/change" {
			forbidden.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body><a href="/logout">logout</a><a href="/excluded?q=x">excluded</a><a href="/included?q=x">included</a><form method="post" action="/change"><input name="new" type="password"></form></body>`)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output := filepath.Join(t.TempDir(), "scope.json")
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecurityCLIProcess$", "--", "--url", server.URL, "--allow-private", "--types", "reflected", "--verify-execution=false", "--crawl", "--exclude-url", "/excluded", "--include-url", "^"+regexp.QuoteMeta(server.URL)+"(?:/(?:included.*|change))?$", "--silent", "--max-payloads", "1", "--output", output)
	process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1")
	_ = process.Run()
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if forbidden.Load() != 0 {
		t.Fatal("unsafe or excluded route reached")
	}
	for _, reason := range []string{"unsafe action path skipped", "excluded by --exclude-url", "password form skipped"} {
		if !strings.Contains(string(data), reason) {
			t.Fatalf("missing report reason %q", reason)
		}
	}
}

func TestDiscoveryUnsafeRedirectIsNotFollowed(t *testing.T) {
	var reached atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/safe" {
			http.Redirect(w, r, "/logout", http.StatusFound)
			return
		}
		reached.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<body>logged out</body>")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output := filepath.Join(t.TempDir(), "redirect.json")
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecurityCLIProcess$", "--", "--url", server.URL+"/safe?q=x", "--allow-private", "--types", "reflected", "--verify-execution=false", "--silent", "--max-payloads", "1", "--output", output)
	process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1")
	_ = process.Run()
	if _, err := os.Stat(output); err != nil {
		t.Fatal(err)
	}
	if reached.Load() != 0 {
		t.Fatal("unsafe redirect destination reached")
	}
}

func TestBrowserDiscoveryUnsafeRedirectIsNotFollowed(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome required; full CI enforces this identity")
	}
	var reached atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/safe" {
			http.Redirect(w, r, "/logout", http.StatusFound)
			return
		}
		reached.Add(1)
		fmt.Fprint(w, "<body>logout</body>")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output := filepath.Join(t.TempDir(), "browser-redirect.json")
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecurityCLIProcess$", "--", "--url", server.URL+"/safe?q=x", "--allow-private", "--types", "dom", "--verify-execution=false", "--silent", "--output", output)
	process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1")
	_ = process.Run()
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if reached.Load() != 0 {
		t.Fatal("browser followed unsafe navigation")
	}
	if !strings.Contains(string(data), "unsafe action path skipped") {
		t.Fatal("browser skip reason not reported")
	}
}

func TestStoredNoFormsDoesNotFollowFormActions(t *testing.T) {
	var reached atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/submitted" {
			reached.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<body><form action="/submitted"><input name="q"></form></body>`)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output := filepath.Join(t.TempDir(), "stored-noforms.json")
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecurityCLIProcess$", "--", "--url", server.URL+"?q=x", "--allow-private", "--types", "stored", "--verify-execution=false", "--no-forms", "--stored-max-polls", "1", "--silent", "--output", output)
	process.Env = append(os.Environ(), "XSSCAN_SECURITY_CLI_TEST=1")
	_ = process.Run()
	if _, err := os.Stat(output); err != nil {
		t.Fatal(err)
	}
	if reached.Load() != 0 {
		t.Fatal("stored discovery followed form action with no-forms")
	}
}
