package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"strings"
)

// resolveCredentials runs after YAML merging; only explicitly supplied CLI values
// outrank the environment. Readers are injected so tests never consume global stdin.
func resolveCredentials(config *ScanConfig, flags map[string]bool, getenv func(string) (string, bool), input io.Reader, warnings io.Writer) error {
	for _, source := range []struct {
		flag, env string
		value     *string
	}{
		{"password", "XSSCAN_PASSWORD", &config.Password},
		{"proxy-password", "XSSCAN_PROXY_PASSWORD", &config.ProxyPassword},
		{"oauth-client-secret", "XSSCAN_OAUTH_CLIENT_SECRET", &config.OAuthClientSecret},
		{"oauth-password", "XSSCAN_OAUTH_PASSWORD", &config.OAuthPassword},
		{"jwt", "XSSCAN_JWT", &config.JWT},
	} {
		if !flags[source.flag] {
			if value, ok := getenv(source.env); ok {
				*source.value = value
			}
		}
	}
	passwordSources := 0
	for _, name := range []string{"password", "password-file", "password-stdin"} {
		if flags[name] && (name != "password-stdin" || config.PasswordStdin) {
			passwordSources++
		}
	}
	if passwordSources > 1 || (flags["jwt"] && flags["jwt-file"]) {
		return fmt.Errorf("choose a single explicit credential source per password or JWT")
	}
	readFile := func(path string) (string, error) {
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("cannot read credential file: %w", err)
		}
		return strings.TrimRight(string(contents), "\r\n"), nil
	}
	if flags["password-file"] {
		value, err := readFile(config.PasswordFile)
		if err != nil {
			return err
		}
		config.Password = value
	}
	if flags["jwt-file"] {
		value, err := readFile(config.JWTFile)
		if err != nil {
			return err
		}
		config.JWT = value
	}
	if config.PasswordStdin {
		if config.TargetsFile == "-" || (config.URL == "" && config.TargetsFile == "") {
			return fmt.Errorf("--password-stdin cannot share stdin with target URLs; provide --url or a targets file")
		}
		contents, err := io.ReadAll(io.LimitReader(input, 1024*1024+1))
		if err != nil {
			return fmt.Errorf("cannot read password stdin: %w", err)
		}
		if len(contents) > 1024*1024 {
			return fmt.Errorf("password stdin exceeds 1 MiB")
		}
		config.Password = strings.TrimRight(string(contents), "\r\n")
	}
	if config.Silent {
		return nil
	}
	risky := false
	for _, name := range []string{"password", "proxy-password", "oauth-client-secret", "oauth-password", "jwt", "cookie"} {
		risky = risky || flags[name]
	}
	if flags["header"] {
		for _, header := range config.Headers {
			name, _, _ := strings.Cut(header, ":")
			if strings.EqualFold(strings.TrimSpace(name), "Authorization") || strings.EqualFold(strings.TrimSpace(name), "Cookie") {
				risky = true
			}
		}
	}
	if flags["proxy"] {
		if u, err := url.Parse(config.Proxy); err == nil && u.User != nil {
			risky = true
		}
	}
	if risky {
		fmt.Fprintln(warnings, "[WARNING] Credentials supplied through argv may be visible in shell history and process lists; prefer environment or credential files/stdin")
	}
	if runtime.GOOS != "windows" && config.ConfigFile != "" {
		file, err := LoadConfig(config.ConfigFile)
		if err != nil {
			return err
		}
		sensitive := file.Password != "" || file.ProxyPassword != "" || file.OAuthClientSecret != "" || file.OAuthPassword != "" || file.JWT != "" || len(file.Cookies) > 0
		for _, header := range file.Headers {
			name, _, _ := strings.Cut(header, ":")
			if strings.EqualFold(strings.TrimSpace(name), "Authorization") || strings.EqualFold(strings.TrimSpace(name), "Cookie") {
				sensitive = true
			}
		}
		if u, err := url.Parse(file.Proxy); err == nil && u.User != nil {
			sensitive = true
		}
		if sensitive {
			info, err := os.Stat(config.ConfigFile)
			if err != nil {
				return err
			}
			if info.Mode().Perm()&0044 != 0 {
				fmt.Fprintln(warnings, "[WARNING] YAML credentials are readable by group/other users; restrict configuration permissions to 0600")
			}
		}
	}
	return nil
}
