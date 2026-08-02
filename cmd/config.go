package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// FileConfig represents a YAML configuration file that sets default scan options.
// CLI flags always take precedence over file config values.
type FileConfig struct {
	URL             string   `yaml:"url"`
	Method          string   `yaml:"method"`
	Headers         []string `yaml:"headers"`
	Body            string   `yaml:"body"`
	Cookies         []string `yaml:"cookies"`
	Output          string   `yaml:"output"`
	Format          string   `yaml:"format"`
	Workers         int      `yaml:"workers"`
	RateLimit       int      `yaml:"rate-limit"`
	Timeout         int      `yaml:"timeout"`
	MaxPayload      int      `yaml:"max-payloads"`
	Callback        string   `yaml:"callback"`
	Verbose         bool     `yaml:"verbose"`
	LoginURL        string   `yaml:"login-url"`
	Username        string   `yaml:"username"`
	Password        string   `yaml:"password"`
	TestHPP         bool     `yaml:"hpp"`
	WAFBypass       bool     `yaml:"waf-bypass"`
	ConfidenceMin   float64  `yaml:"confidence"`
	AllowPrivate    bool     `yaml:"allow-private"`
	Proxy           string   `yaml:"proxy"`
	ProxyUsername   string   `yaml:"proxy-username"`
	ProxyPassword   string   `yaml:"proxy-password"`
	ProxyInsecure   bool     `yaml:"proxy-insecure"`
	Crawl           bool     `yaml:"crawl"`
	CrawlDepth      int      `yaml:"crawl-depth"`
	CrawlMaxPages   int      `yaml:"crawl-max-pages"`
	TargetsFile     string   `yaml:"targets-file"`
	RandomUA        bool     `yaml:"random-ua"`
	AdaptiveRate    bool     `yaml:"adaptive-rate"`
	PayloadPreset   string   `yaml:"payload-preset"`
	PayloadWordlist string   `yaml:"payload-wordlist"`
	Headless        bool     `yaml:"headless"`
	JWT             string   `yaml:"jwt"`
}

// LoadConfig reads a YAML config file and applies its values to ScanConfig.
// Only fields with non-zero values from the file are applied — this lets
// CLI flags override the config file when explicitly set.
func LoadConfig(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}

	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("invalid YAML config: %w", err)
	}

	return &fc, nil
}

// ApplyTo applies file config values to ScanConfig, but only for fields
// where the CLI flag was not explicitly set (i.e., still at zero value).
func (fc *FileConfig) ApplyTo(cfg *ScanConfig, flags map[string]bool) {
	if fc.URL != "" && !flags["url"] {
		cfg.URL = fc.URL
	}
	if fc.Method != "" && !flags["method"] {
		cfg.Method = fc.Method
	}
	if len(fc.Headers) > 0 && !flags["header"] {
		cfg.Headers = fc.Headers
	}
	if fc.Body != "" && !flags["data"] {
		cfg.Body = fc.Body
	}
	if len(fc.Cookies) > 0 && !flags["cookie"] {
		cfg.Cookies = fc.Cookies
	}
	if fc.Output != "" && !flags["output"] {
		cfg.Output = fc.Output
	}
	if fc.Format != "" && !flags["format"] {
		cfg.Format = fc.Format
	}
	if fc.Workers != 0 && !flags["workers"] {
		cfg.Workers = fc.Workers
	}
	if fc.RateLimit != 0 && !flags["rate-limit"] {
		cfg.RateLimit = fc.RateLimit
	}
	if fc.Timeout != 0 && !flags["timeout"] {
		cfg.Timeout = fc.Timeout
	}
	if fc.MaxPayload != 0 && !flags["max-payloads"] {
		cfg.MaxPayload = fc.MaxPayload
	}
	if fc.Callback != "" && !flags["callback"] {
		cfg.Callback = fc.Callback
	}
	if fc.Verbose && !flags["verbose"] {
		cfg.Verbose = fc.Verbose
	}
	if fc.LoginURL != "" && !flags["login-url"] {
		cfg.LoginURL = fc.LoginURL
	}
	if fc.Username != "" && !flags["username"] {
		cfg.Username = fc.Username
	}
	if fc.Password != "" && !flags["password"] {
		cfg.Password = fc.Password
	}
	if fc.TestHPP && !flags["hpp"] {
		cfg.TestHPP = fc.TestHPP
	}
	if fc.WAFBypass && !flags["waf-bypass"] {
		cfg.WAFBypass = fc.WAFBypass
	}
	if fc.ConfidenceMin != 0 && !flags["confidence"] {
		cfg.ConfidenceMin = fc.ConfidenceMin
	}
	if fc.AllowPrivate && !flags["allow-private"] {
		cfg.AllowPrivate = fc.AllowPrivate
	}
	if fc.Proxy != "" && !flags["proxy"] {
		cfg.Proxy = fc.Proxy
	}
	if fc.ProxyUsername != "" && !flags["proxy-username"] {
		cfg.ProxyUsername = fc.ProxyUsername
	}
	if fc.ProxyPassword != "" && !flags["proxy-password"] {
		cfg.ProxyPassword = fc.ProxyPassword
	}
	if fc.ProxyInsecure && !flags["proxy-insecure"] {
		cfg.ProxyInsecure = fc.ProxyInsecure
	}
	if fc.Crawl && !flags["crawl"] {
		cfg.Crawl = fc.Crawl
	}
	if fc.CrawlDepth != 0 && !flags["crawl-depth"] {
		cfg.CrawlDepth = fc.CrawlDepth
	}
	if fc.CrawlMaxPages != 0 && !flags["crawl-max-pages"] {
		cfg.CrawlMaxPages = fc.CrawlMaxPages
	}
	if fc.TargetsFile != "" && !flags["targets-file"] {
		cfg.TargetsFile = fc.TargetsFile
	}
	if fc.RandomUA && !flags["random-ua"] {
		cfg.RandomUA = fc.RandomUA
	}
	if fc.AdaptiveRate && !flags["adaptive-rate"] {
		cfg.AdaptiveRate = fc.AdaptiveRate
	}
	if fc.PayloadPreset != "" && !flags["payload-preset"] {
		cfg.PayloadPreset = fc.PayloadPreset
	}
	if fc.PayloadWordlist != "" && !flags["payload-wordlist"] {
		cfg.PayloadWordlist = fc.PayloadWordlist
	}
	if fc.Headless && !flags["headless"] {
		cfg.Headless = fc.Headless
	}
	if fc.JWT != "" && !flags["jwt"] {
		cfg.JWT = fc.JWT
	}
}
