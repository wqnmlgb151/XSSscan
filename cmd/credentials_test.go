package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCredentialEnvironmentAndExplicitEmpty(t *testing.T) {
	config := ScanConfig{Password: "yaml", ProxyPassword: "yaml", OAuthClientSecret: "yaml", OAuthPassword: "yaml", JWT: "yaml", Silent: true}
	env := func(name string) (string, bool) { return "env-" + name, true }
	if err := resolveCredentials(&config, map[string]bool{"jwt": true}, env, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if config.Password != "env-XSSCAN_PASSWORD" || config.ProxyPassword != "env-XSSCAN_PROXY_PASSWORD" || config.OAuthClientSecret != "env-XSSCAN_OAUTH_CLIENT_SECRET" || config.OAuthPassword != "env-XSSCAN_OAUTH_PASSWORD" || config.JWT != "yaml" {
		t.Fatalf("environment precedence incorrect: %+v", config)
	}
	config.JWT = ""
	if err := resolveCredentials(&config, map[string]bool{"jwt": true}, env, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if config.JWT != "" {
		t.Fatal("explicit empty value overridden")
	}
}

func TestPasswordFileAndStdinSources(t *testing.T) {
	env := func(string) (string, bool) { return "environment", true }
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(" password value \r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := ScanConfig{PasswordFile: path, Silent: true}
	if err := resolveCredentials(&config, map[string]bool{"password-file": true}, env, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if config.Password != " password value " {
		t.Fatal("file value or significant spaces changed")
	}
	config = ScanConfig{PasswordStdin: true, URL: "http://127.0.0.1/", Silent: true}
	if err := resolveCredentials(&config, map[string]bool{"password-stdin": true}, env, strings.NewReader("stdin-password\n"), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if config.Password != "stdin-password" {
		t.Fatal("stdin source ignored")
	}
	config.TargetsFile = "-"
	if err := resolveCredentials(&config, map[string]bool{"password-stdin": true}, env, strings.NewReader("unused"), &bytes.Buffer{}); err == nil {
		t.Fatal("stdin sharing accepted")
	}
	if err := resolveCredentials(&config, map[string]bool{"password": true, "password-file": true}, env, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("conflicting explicit sources accepted")
	}
}

func TestYAMLCredentialPermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	} // POSIX permission semantics are exercised by Linux CI.
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("password: synthetic-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	var warnings bytes.Buffer
	config := ScanConfig{ConfigFile: path}
	missing := func(string) (string, bool) { return "", false }
	if err := resolveCredentials(&config, nil, missing, strings.NewReader(""), &warnings); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warnings.String(), "0600") || strings.Contains(warnings.String(), "synthetic-password") {
		t.Fatal("unsafe YAML warning missing or leaked value")
	}
	warnings.Reset()
	config.Silent = true
	if err := resolveCredentials(&config, nil, missing, strings.NewReader(""), &warnings); err != nil {
		t.Fatal(err)
	}
	if warnings.Len() != 0 {
		t.Fatal("silent permission warning emitted")
	}
}

func TestAllSensitiveArgvWarningsAreSilentAware(t *testing.T) {
	for _, name := range []string{"password", "proxy-password", "oauth-client-secret", "oauth-password", "jwt", "cookie", "header", "proxy"} {
		config := ScanConfig{Headers: []string{"Authorization: Bearer synthetic"}, Proxy: "http://user:synthetic@127.0.0.1:1"}
		var warnings bytes.Buffer
		missing := func(string) (string, bool) { return "", false }
		if err := resolveCredentials(&config, map[string]bool{name: true}, missing, strings.NewReader(""), &warnings); err != nil {
			t.Fatal(err)
		}
		if strings.Count(warnings.String(), "[WARNING]") != 1 || strings.Contains(warnings.String(), "synthetic") {
			t.Fatalf("%s warning missing, repeated or leaked", name)
		}
		warnings.Reset()
		config.Silent = true
		if err := resolveCredentials(&config, map[string]bool{name: true}, missing, strings.NewReader(""), &warnings); err != nil {
			t.Fatal(err)
		}
		if warnings.Len() != 0 {
			t.Fatalf("%s silent warning", name)
		}
	}
}
