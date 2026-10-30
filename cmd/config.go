package main

import (
	"bytes"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"reflect"
)

// FileConfig records which YAML keys were provided, including false and zero.
type FileConfig struct {
	present                map[string]bool
	OAuthAllowedOrigins    []string `yaml:"oauth-allow-origin"`
	LoginSuccessContains   string   `yaml:"login-success-contains"`
	LoginSuccessURL        string   `yaml:"login-success-url"`
	Types                  string   `yaml:"types"`
	ExcludeTypes           string   `yaml:"exclude-types"`
	ModuleTimeout          int      `yaml:"module-timeout"`
	RequestBudget          int      `yaml:"request-budget"`
	URL                    string   `yaml:"url"`
	Method                 string   `yaml:"method"`
	Headers                []string `yaml:"headers"`
	Body                   string   `yaml:"body"`
	Cookies                []string `yaml:"cookies"`
	Output                 string   `yaml:"output"`
	Format                 string   `yaml:"format"`
	Workers                int      `yaml:"workers"`
	RateLimit              int      `yaml:"rate-limit"`
	Timeout                int      `yaml:"timeout"`
	MaxPayload             int      `yaml:"max-payloads"`
	Callback               string   `yaml:"callback"`
	Verbose                bool     `yaml:"verbose"`
	LoginURL               string   `yaml:"login-url"`
	Username               string   `yaml:"username"`
	Password               string   `yaml:"password"`
	TestHPP                bool     `yaml:"hpp"`
	WAFBypass              bool     `yaml:"waf-bypass"`
	ConfidenceMin          float64  `yaml:"confidence"`
	AllowPrivate           bool     `yaml:"allow-private"`
	Proxy                  string   `yaml:"proxy"`
	ProxyUsername          string   `yaml:"proxy-username"`
	ProxyPassword          string   `yaml:"proxy-password"`
	ProxyInsecure          bool     `yaml:"proxy-insecure"`
	Crawl                  bool     `yaml:"crawl"`
	CrawlDepth             int      `yaml:"crawl-depth"`
	CrawlMaxPages          int      `yaml:"crawl-max-pages"`
	TargetsFile            string   `yaml:"targets-file"`
	RandomUA               bool     `yaml:"random-ua"`
	AdaptiveRate           bool     `yaml:"adaptive-rate"`
	Strategy               string   `yaml:"strategy"`
	PayloadPreset          string   `yaml:"payload-preset"`
	PayloadWordlist        string   `yaml:"payload-wordlist"`
	Headless               bool     `yaml:"headless"`
	RenderSPA              bool     `yaml:"render-spa"`
	ChromeNoSandbox        bool     `yaml:"chrome-no-sandbox"`
	ChromeIgnoreCertErrors bool     `yaml:"chrome-ignore-cert-errors"`
	ChromePath             string   `yaml:"chrome-path"`
	JWT                    string   `yaml:"jwt"`
	Silent                 bool     `yaml:"silent"`
	NoColor                bool     `yaml:"no-color"`
	EnableProbe            bool     `yaml:"probe"`
	VerifyExecution        bool     `yaml:"verify-execution"`
	VerifyTimeout          int      `yaml:"verify-timeout"`
	DiscoverHeaders        bool     `yaml:"discover-headers"`
	EnableStored           bool     `yaml:"stored"`
	TriggerURLs            []string `yaml:"trigger-urls"`
	StoredPollInterval     int      `yaml:"stored-poll-interval"`
	StoredMaxPolls         int      `yaml:"stored-max-polls"`
	CSRFToken              string   `yaml:"csrf-token"`
	OAuthIssuer            string   `yaml:"oauth-issuer"`
	OAuthClientID          string   `yaml:"oauth-client-id"`
	OAuthClientSecret      string   `yaml:"oauth-client-secret"`
	OAuthUsername          string   `yaml:"oauth-username"`
	OAuthPassword          string   `yaml:"oauth-password"`
	OAuthScope             string   `yaml:"oauth-scope"`
}

func LoadConfig(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	fc := &FileConfig{present: map[string]bool{}}
	if err := decoder.Decode(fc); err != nil && err != io.EOF {
		return nil, fmt.Errorf("invalid YAML config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("config must contain one YAML document")
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	if len(node.Content) > 0 {
		root := node.Content[0]
		if root.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("config must be a mapping")
		}
		for i := 0; i < len(root.Content); i += 2 {
			key := root.Content[i].Value
			if key == "<<" {
				return nil, fmt.Errorf("YAML merge keys are unsupported; write explicit configuration keys")
			}
			fc.present[key] = true
		}
	}
	return fc, nil
}
func (fc *FileConfig) ApplyTo(cfg *ScanConfig, flags map[string]bool) {
	source := reflect.ValueOf(fc).Elem()
	dest := reflect.ValueOf(cfg).Elem()
	typ := source.Type()
	for i := 0; i < source.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		key := field.Tag.Get("yaml")
		flag := configFlags[field.Name]
		value := source.Field(i)
		if flags[flag] || (!fc.present[key] && value.IsZero()) {
			continue
		}
		dest.FieldByName(field.Name).Set(value)
		if field.Name == "Headless" || field.Name == "EnableStored" {
			if cfg.legacyTypeFlags == nil {
				cfg.legacyTypeFlags = map[string]bool{}
			}
			cfg.legacyTypeFlags[flag] = value.Bool()
		}
	}
	cfg.typesExplicit = fc.present["types"] || flags["types"]
}

var configFlags = map[string]string{
	"OAuthAllowedOrigins":    "oauth-allow-origin",
	"LoginSuccessContains":   "login-success-contains",
	"LoginSuccessURL":        "login-success-url",
	"Types":                  "types",
	"ExcludeTypes":           "exclude-types",
	"ModuleTimeout":          "module-timeout",
	"RequestBudget":          "request-budget",
	"URL":                    "url",
	"Method":                 "method",
	"Headers":                "header",
	"Body":                   "data",
	"Cookies":                "cookie",
	"Output":                 "output",
	"Format":                 "format",
	"Workers":                "workers",
	"RateLimit":              "rate-limit",
	"Timeout":                "timeout",
	"MaxPayload":             "max-payloads",
	"Callback":               "callback",
	"Verbose":                "verbose",
	"LoginURL":               "login-url",
	"Username":               "username",
	"Password":               "password",
	"TestHPP":                "hpp",
	"WAFBypass":              "waf-bypass",
	"ConfidenceMin":          "confidence",
	"AllowPrivate":           "allow-private",
	"Proxy":                  "proxy",
	"ProxyUsername":          "proxy-username",
	"ProxyPassword":          "proxy-password",
	"ProxyInsecure":          "proxy-insecure",
	"Crawl":                  "crawl",
	"CrawlDepth":             "crawl-depth",
	"CrawlMaxPages":          "crawl-max-pages",
	"TargetsFile":            "targets-file",
	"RandomUA":               "random-ua",
	"AdaptiveRate":           "adaptive-rate",
	"Strategy":               "strategy",
	"PayloadPreset":          "payload-preset",
	"PayloadWordlist":        "payload-wordlist",
	"Headless":               "headless",
	"RenderSPA":              "render-spa",
	"ChromeNoSandbox":        "chrome-no-sandbox",
	"ChromeIgnoreCertErrors": "chrome-ignore-cert-errors",
	"ChromePath":             "chrome-path",
	"JWT":                    "jwt",
	"Silent":                 "silent",
	"NoColor":                "no-color",
	"EnableProbe":            "probe",
	"VerifyExecution":        "verify-execution",
	"VerifyTimeout":          "verify-timeout",
	"DiscoverHeaders":        "discover-headers",
	"EnableStored":           "stored",
	"TriggerURLs":            "trigger-url",
	"StoredPollInterval":     "stored-poll-interval",
	"StoredMaxPolls":         "stored-max-polls",
	"CSRFToken":              "csrf-token",
	"OAuthIssuer":            "oauth-issuer",
	"OAuthClientID":          "oauth-client-id",
	"OAuthClientSecret":      "oauth-client-secret",
	"OAuthUsername":          "oauth-username",
	"OAuthPassword":          "oauth-password",
	"OAuthScope":             "oauth-scope",
}
