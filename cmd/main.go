package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/auth"
	"github.com/xsscan/xsscan/pkg/auth/oauth"
	"github.com/xsscan/xsscan/pkg/callback"
	"github.com/xsscan/xsscan/pkg/crawler"
	"github.com/xsscan/xsscan/pkg/dom"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/report"
	"github.com/xsscan/xsscan/pkg/scanner"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/pkg/stored"
	"go.uber.org/zap"
)

const (
	contentTypeHeader = "Content-Type"
	formURLEncoded    = "application/x-www-form-urlencoded"
)

// ScanConfig holds all CLI flags
type ScanConfig struct {
	URL        string
	Method     string
	Headers    []string
	Body       string
	Cookies    []string
	Output     string
	Format     string
	Workers    int
	RateLimit  int
	Timeout    int
	MaxPayload int
	Callback   string
	Verbose    bool
	LoginURL      string
	Username      string
	Password      string
	TestHPP       bool
	WAFBypass     bool
	ConfidenceMin float64
	AllowPrivate  bool
	Proxy         string
	ProxyUsername string
	ProxyPassword string
	ProxyInsecure bool
	Crawl         bool
	CrawlDepth    int
	CrawlMaxPages int
	TargetsFile   string
	RandomUA      bool
	AdaptiveRate  bool
	PayloadPreset  string
	PayloadWordlist string
	Headless       bool
	RenderSPA      bool
	ConfigFile     string
	JWT            string
	Silent         bool
	NoColor        bool
	EnableProbe      bool
	VerifyExecution  bool
	VerifyTimeout    int
	DiscoverHeaders  bool
	EnableStored     bool
	TriggerURLs    []string
	StoredPollInterval int
	StoredMaxPolls     int
	CSRFToken          string

	// OAuth 2.0
	OAuthIssuer       string
	OAuthClientID     string
	OAuthClientSecret string
	OAuthUsername     string
	OAuthPassword     string
	OAuthScope        string
}

const (
	maxWorkers        = 1000
	defaultMaxPayload = 50
	minRateLimit      = 1
	minTimeout        = 1
)

// Version is the current xsscan version. Set via ldflags at build time:
//
//	make build VERSION=1.0.0
//
// x.y.z: x = major (architectural redesign), y = feature, z = bug fix.
var Version = "0.6.0"

var cfg ScanConfig

var rootCmd = &cobra.Command{
	Use:   "xsscan",
	Short: "xsscan - 下一代上下文感知 XSS 扫描器",
	Long: `xsscan - 下一代上下文感知 XSS 扫描器

支持反射型 XSS 检测，上下文感知 payload 生成，
前端框架识别，CSP 分析和 WAF 绕过。
支持存储型 XSS 检测（需要 --stored 和 --trigger-url）。

支持 Query、POST Body (JSON/Form)、Header、Cookie 参数注入。
支持管道输入：echo http://target | xsscan

仅用于授权的安全测试。`,
	Version: Version,
	RunE:    runScan,
}

const (
	ExitOK         = 0
	ExitError      = 1
	ExitVulnerable = 2
)

var findingsCount int

func Execute() error {
	return rootCmd.Execute()
}

func main() {
	if err := Execute(); err != nil {
		if !cfg.Silent {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(ExitError)
	}
	if findingsCount > 0 {
		os.Exit(ExitVulnerable)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&cfg.URL, "url", "u", "", "Target URL (required)")
	rootCmd.Flags().StringVarP(&cfg.Method, "method", "X", "GET", "HTTP method")
	rootCmd.Flags().StringArrayVarP(&cfg.Headers, "header", "H", nil, "Custom headers (Key:Value)")
	rootCmd.Flags().StringVarP(&cfg.Body, "data", "d", "", "POST body (form-urlencoded or JSON)")
	rootCmd.Flags().StringArrayVarP(&cfg.Cookies, "cookie", "c", nil, "Pre-authenticated cookies (Name=Value, seeds cookie jar)")
	rootCmd.Flags().StringVarP(&cfg.Output, "output", "o", "", "Output file path")
	rootCmd.Flags().StringVarP(&cfg.Format, "format", "f", "json", "Output format: json, markdown, html")
	rootCmd.Flags().IntVarP(&cfg.Workers, "workers", "w", 10, "Concurrent workers")
	rootCmd.Flags().IntVar(&cfg.RateLimit, "rate-limit", 100, "Max requests per second")
	rootCmd.Flags().IntVarP(&cfg.Timeout, "timeout", "t", 30, "Request timeout (seconds)")
	rootCmd.Flags().IntVar(&cfg.MaxPayload, "max-payloads", defaultMaxPayload, "Max payloads per param (0=unlimited)")
	rootCmd.Flags().StringVar(&cfg.Callback, "callback", "", "Blind XSS callback URL")
	rootCmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().StringVar(&cfg.LoginURL, "login-url", "", "Login URL for authenticated scanning")
	rootCmd.Flags().StringVar(&cfg.Username, "username", "", "Username for login")
	rootCmd.Flags().StringVar(&cfg.Password, "password", "", "Password for login")
	rootCmd.Flags().BoolVar(&cfg.TestHPP, "hpp", false, "Enable HTTP Parameter Pollution testing")
	rootCmd.Flags().BoolVar(&cfg.WAFBypass, "waf-bypass", false, "Enable WAF bypass via payload mutation")
	rootCmd.Flags().Float64Var(&cfg.ConfidenceMin, "confidence", 0.60, "Minimum confidence threshold (0.0-1.0)")
	rootCmd.Flags().BoolVar(&cfg.AllowPrivate, "allow-private", false, "Allow scanning private/internal networks (SSRF protection bypass)")
	rootCmd.Flags().StringVar(&cfg.Proxy, "proxy", "", "HTTP proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)")
	rootCmd.Flags().StringVar(&cfg.ProxyUsername, "proxy-username", "", "Proxy basic auth username (optional)")
	rootCmd.Flags().StringVar(&cfg.ProxyPassword, "proxy-password", "", "Proxy basic auth password (optional)")
	rootCmd.Flags().BoolVar(&cfg.ProxyInsecure, "proxy-insecure", false, "Skip TLS verification for proxy (useful with Burp self-signed CA)")
	rootCmd.Flags().BoolVar(&cfg.Crawl, "crawl", false, "Enable link discovery crawling before scanning")
	rootCmd.Flags().IntVar(&cfg.CrawlDepth, "crawl-depth", 2, "Maximum crawl depth (0 = start URL only)")
	rootCmd.Flags().IntVar(&cfg.CrawlMaxPages, "crawl-max-pages", 50, "Maximum pages to crawl")
	rootCmd.Flags().StringVarP(&cfg.TargetsFile, "targets-file", "l", "", "File with target URLs (one per line, \"-\" for stdin)")
	rootCmd.Flags().BoolVar(&cfg.RandomUA, "random-ua", false, "Randomize User-Agent per request")
	rootCmd.Flags().BoolVar(&cfg.AdaptiveRate, "adaptive-rate", false, "Auto-adjust rate limit on 429 responses")
	rootCmd.Flags().StringVar(&cfg.PayloadPreset, "payload-preset", "standard", "Payload preset: minimal, standard, full")
	rootCmd.Flags().BoolVar(&cfg.Headless, "headless", false, "Enable headless browser for DOM XSS detection (requires Chrome)")
	rootCmd.Flags().BoolVar(&cfg.RenderSPA, "render-spa", false, "Use headless Chrome to render SPA pages for form discovery (requires Chrome)")
	rootCmd.Flags().StringVar(&cfg.PayloadWordlist, "payload-wordlist", "", "Path to custom payload wordlist (one payload per line)")
	rootCmd.Flags().StringVar(&cfg.ConfigFile, "config", "", "Path to YAML config file")
	rootCmd.Flags().StringVar(&cfg.JWT, "jwt", "", "JWT token (sent as Bearer in Authorization header)")
	rootCmd.Flags().BoolVar(&cfg.Silent, "silent", false, "Suppress banner and status output (for pipelines)")
	rootCmd.Flags().BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI color output")
	rootCmd.Flags().BoolVar(&cfg.EnableProbe, "probe", false, "Run context probes before payload scanning (reduces false positives)")
	rootCmd.Flags().BoolVar(&cfg.VerifyExecution, "verify-execution", false, "Verify XSS execution in real browser (requires Chrome, increases accuracy)")
	rootCmd.Flags().IntVar(&cfg.VerifyTimeout, "verify-timeout", 15, "Per-finding verification timeout in seconds (with --verify-execution)")
	rootCmd.Flags().BoolVar(&cfg.DiscoverHeaders, "discover-headers", false, "Auto-discover dangerous headers as injection points (X-Forwarded-Host, Referer, etc.)")
	rootCmd.Flags().BoolVar(&cfg.EnableStored, "stored", false, "Enable stored XSS detection (requires --trigger-url)")
	rootCmd.Flags().StringArrayVar(&cfg.TriggerURLs, "trigger-url", nil, "URL(s) where stored content may appear (repeatable, required for --stored)")
	rootCmd.Flags().IntVar(&cfg.StoredPollInterval, "stored-poll-interval", 2, "Polling interval in seconds for stored XSS detection")
	rootCmd.Flags().IntVar(&cfg.StoredMaxPolls, "stored-max-polls", 5, "Max polls per injection for stored XSS detection")
	rootCmd.Flags().StringVar(&cfg.CSRFToken, "csrf-token", "", "CSRF token for authenticated scanning (auto-detected if not provided)")

	// OAuth 2.0 flags
	rootCmd.Flags().StringVar(&cfg.OAuthIssuer, "oauth-issuer", "", "OIDC/OAuth 2.0 issuer URL")
	rootCmd.Flags().StringVar(&cfg.OAuthClientID, "oauth-client-id", "", "OAuth 2.0 client ID")
	rootCmd.Flags().StringVar(&cfg.OAuthClientSecret, "oauth-client-secret", "", "OAuth 2.0 client secret (optional for public clients)")
	rootCmd.Flags().StringVar(&cfg.OAuthUsername, "oauth-username", "", "OAuth 2.0 username (for ROPC flow)")
	rootCmd.Flags().StringVar(&cfg.OAuthPassword, "oauth-password", "", "OAuth 2.0 password (for ROPC flow)")
	rootCmd.Flags().StringVar(&cfg.OAuthScope, "oauth-scope", "openid profile", "OAuth 2.0 scope (default: openid profile)")

	rootCmd.MarkFlagsMutuallyExclusive("url", "targets-file")
}

func runScan(cmd *cobra.Command, args []string) error {
	if cfg.NoColor {
		color.NoColor = true
	}
	if !cfg.Silent {
		printBanner()
	}

	if err := loadAndValidateConfig(cmd); err != nil {
		return err
	}
	logger := setupLogger()
	defer logger.Sync()

	headers := parseHeaders(cfg.Headers)
	if cfg.JWT != "" {
		headers["Authorization"] = "Bearer " + cfg.JWT
		color.Cyan("[*] JWT token configured (Authorization: Bearer)\n")
	}
	target := model.Target{
		URL:     cfg.URL,
		Method:  cfg.Method,
		Headers: headers,
		Body:    cfg.Body,
		Cookies: parseCookies(cfg.Cookies),
	}

	client, proxyConfig, err := setupHTTPClient(target)
	if err != nil {
		return err
	}
	target = applyProxyAuth(target, proxyConfig)

	if err := setupAuthentication(client, headers, target); err != nil {
		return err
	}

	seedCookieJar(client, target)

	engine := scanner.NewEngine(buildEngineConfig(), logger, client)
	callbackSrv := setupCallbackServer(cfg.Callback, engine)
	if cfg.PayloadPreset != "" {
		engine.SetPayloadPreset(payload.PayloadPreset(cfg.PayloadPreset))
	}
	if cfg.PayloadWordlist != "" {
		if err := engine.SetWordlist(cfg.PayloadWordlist); err != nil {
			return fmt.Errorf("failed to load payload wordlist: %w", err)
		}
		color.Cyan("[*] Loaded custom payload wordlist: %s\n", cfg.PayloadWordlist)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupSignalHandler(cancel)

	urls, err := resolveTargets(target.URL)
	if err != nil {
		return err
	}
	color.Cyan("[*] Scanning %d target(s)...\n", len(urls))
	startTime := time.Now()

	var allFindings []model.Finding
	var totalStats model.ScanStats
	if err := scanAllTargets(ctx, engine, client, urls, target, &allFindings, &totalStats); err != nil {
		return err
	}

	if callbackSrv != nil {
		collectBlindXSSCallbacks(callbackSrv, &allFindings, cfg.Callback, urls)
	}

	return reportScanResults(allFindings, totalStats, urls, startTime)
}

func loadAndValidateConfig(cmd *cobra.Command) error {
	if cfg.ConfigFile != "" {
		fc, err := LoadConfig(cfg.ConfigFile)
		if err != nil {
			return err
		}
		flags := collectChangedFlags(cmd)
		fc.ApplyTo(&cfg, flags)
		color.Cyan("[*] Loaded config from %s\n", cfg.ConfigFile)
	}
	ssrfguard.AllowPrivate = cfg.AllowPrivate
	return validateConfig(&cfg)
}

func setupLogger() *zap.Logger {
	logCfg := zap.NewProductionConfig()
	if cfg.Verbose {
		logCfg.Level.SetLevel(zap.DebugLevel)
	}
	logger, err := logCfg.Build()
	if err != nil {
		return zap.NewNop()
	}
	return logger
}

func setupHTTPClient(target model.Target) (*http.Client, *httpclient.ProxyConfig, error) {
	engineCfg := buildEngineConfig()
	var proxyConfig *httpclient.ProxyConfig
	if cfg.Proxy != "" {
		proxyConfig = &httpclient.ProxyConfig{
			URL:      cfg.Proxy,
			Username: cfg.ProxyUsername,
			Password: cfg.ProxyPassword,
			Insecure: cfg.ProxyInsecure,
		}
		if err := proxyConfig.Validate(); err != nil {
			return nil, nil, fmt.Errorf("proxy validation failed: %w", err)
		}
		color.Cyan("[*] Using proxy: %s\n", cfg.Proxy)
	}
	client := httpclient.NewClient(engineCfg.RequestTimeout, proxyConfig)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		if err := ssrfguard.IsURLTargetAllowed(req.URL.String()); err != nil {
			return fmt.Errorf("redirect blocked: %w", err)
		}
		return nil
	}
	return client, proxyConfig, nil
}

func applyProxyAuth(target model.Target, proxyConfig *httpclient.ProxyConfig) model.Target {
	if proxyConfig != nil {
		if authHeader, ok := proxyConfig.ProxyAuthHeader(); ok {
			target.ProxyAuth = authHeader
		}
	}
	return target
}

func setupAuthentication(client *http.Client, headers map[string]string, target model.Target) error {
	if cfg.OAuthIssuer != "" || cfg.OAuthClientID != "" {
		if err := setupOAuth(client, headers); err != nil {
			return err
		}
	}
	if cfg.LoginURL != "" {
		if cfg.Username == "" || cfg.Password == "" {
			return fmt.Errorf("--login-url requires both --username and --password")
		}
		color.Cyan("[*] Authenticating to %s...\n", cfg.LoginURL)
		if err := auth.Authenticate(client, auth.LoginConfig{
			LoginURL: cfg.LoginURL,
			Username: cfg.Username,
			Password: cfg.Password,
		}); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		color.Green("[+] Authentication successful\n")
	}
	if headers["Authorization"] != "" {
		target.Headers["Authorization"] = headers["Authorization"]
	}
	return nil
}

func setupOAuth(client *http.Client, headers map[string]string) error {
	if cfg.OAuthClientID == "" {
		return fmt.Errorf("--oauth-issuer requires --oauth-client-id")
	}
	engineCfg := buildEngineConfig()
	oauthCtx, oauthCancel := context.WithTimeout(context.Background(), engineCfg.RequestTimeout)
	defer oauthCancel()

	color.Cyan("[*] OAuth 2.0 authentication (client: %s)...\n", cfg.OAuthClientID)

	flowCfg := oauth.FlowConfig{
		ClientID:     cfg.OAuthClientID,
		ClientSecret: cfg.OAuthClientSecret,
		Scope:        cfg.OAuthScope,
	}

	if cfg.OAuthIssuer != "" {
		issuer, err := oauth.ExtractIssuer(cfg.OAuthIssuer)
		if err != nil {
			return fmt.Errorf("invalid oauth issuer: %w", err)
		}
		doc, err := oauth.DiscoverOIDC(oauthCtx, client, issuer)
		if err != nil {
			color.Yellow("[!] OIDC discovery failed: %v — using manual endpoints\n", err)
		} else {
			flowCfg.TokenURL = doc.TokenEndpoint
			flowCfg.AuthURL = doc.AuthorizationEndpoint
			color.Cyan("[*] Discovered OAuth endpoints from %s\n", issuer)
		}
	}

	if cfg.OAuthUsername != "" && cfg.OAuthPassword != "" {
		flowCfg.Username = cfg.OAuthUsername
		flowCfg.Password = cfg.OAuthPassword
	}

	flow := oauth.NewFlow(client, flowCfg)

	var tokenPair *oauth.TokenPair
	var oauthErr error
	if flowCfg.Username != "" {
		tokenPair, oauthErr = flow.Authenticate(oauthCtx)
	} else {
		oauthErr = fmt.Errorf("oauth authentication requires --oauth-username and --oauth-password (ROPC flow)")
	}

	if oauthErr != nil {
		return fmt.Errorf("OAuth authentication failed: %w", oauthErr)
	}

	headers["Authorization"] = tokenPair.AuthorizationHeader()
	color.Green("[+] OAuth authentication successful (token type: %s, expires: %s)\n",
		tokenPair.TokenType, time.Unix(int64(tokenPair.ExpiresIn)+time.Now().Unix(), 0).Format("15:04:05"))
	return nil
}

func seedCookieJar(client *http.Client, target model.Target) {
	if len(target.Cookies) > 0 && client.Jar != nil {
		u, err := url.Parse(target.URL)
		if err == nil {
			client.Jar.SetCookies(u, target.Cookies)
		}
	}
}

func setupCallbackServer(callbackURL string, engine *scanner.Engine) *callback.Server {
	if callbackURL == "" {
		return nil
	}
	parsedURL, err := url.Parse(callbackURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		engine.SetCallbackURL(callbackURL)
		return nil
	}
	callbackPort := parsedURL.Port()
	if callbackPort == "" {
		callbackPort = "80"
		if parsedURL.Scheme == "https" {
			callbackPort = "443"
		}
	}
	callbackAddr := ":" + callbackPort
	srv := callback.NewServer(callbackAddr)
	if err := srv.Start(); err != nil {
		color.Yellow("[!] Failed to start callback server on %s: %v — blind XSS may not work\n", callbackAddr, err)
		return nil
	}
	color.Cyan("[*] Callback server listening on %s\n", srv.BaseURL())
	engine.SetCallbackURL(srv.BaseURL())
	return srv
}

func setupSignalHandler(cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		color.Yellow("\n[!] Interrupt received, stopping...")
		cancel()
	}()
}

func resolveTargets(primaryURL string) ([]string, error) {
	var urls []string
	if primaryURL != "" {
		urls = append(urls, primaryURL)
	}
	if cfg.TargetsFile != "" {
		fileURLs, err := loadTargets(cfg.TargetsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load targets: %w", err)
		}
		if cfg.TargetsFile == "-" {
			color.Cyan("[*] Loaded %d targets from stdin\n", len(fileURLs))
		} else if len(fileURLs) > 0 {
			color.Cyan("[*] Loaded %d targets from %s\n", len(fileURLs), cfg.TargetsFile)
		}
		urls = append(urls, fileURLs...)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("no target URLs provided")
	}
	return urls, nil
}

func deriveTarget(base model.Target, urlStr string) model.Target {
	return model.Target{
		URL:       urlStr,
		Method:    base.Method,
		Headers:   cloneHeaders(base.Headers),
		Cookies:   cloneCookies(base.Cookies),
		Body:      base.Body,
		ProxyAuth: base.ProxyAuth,
	}
}

func scanAllTargets(ctx context.Context, engine *scanner.Engine, client *http.Client, urls []string, baseTarget model.Target, allFindings *[]model.Finding, totalStats *model.ScanStats) error {
	for i, scanURL := range urls {
		if len(urls) > 1 {
			color.Cyan("\n[*] [%d/%d] %s\n", i+1, len(urls), scanURL)
		}

		scanTarget := deriveTarget(baseTarget, scanURL)

		if cfg.Crawl {
			if err := crawlAndScan(ctx, client, engine, scanURL, baseTarget, allFindings, totalStats); err != nil {
				if errors.Is(err, context.Canceled) {
					color.Yellow("\n[!] Crawl cancelled")
					return nil
				}
			}
			// Headless/stored scans still run for the seed target in crawl mode
			if err := runHeadlessScan(ctx, client, scanTarget, allFindings); err != nil {
				color.Yellow("[!] Headless scan error: %v\n", err)
			}
			if cfg.EnableStored {
				if err := runStoredXSSScan(ctx, client, scanTarget, allFindings); err != nil {
					color.Yellow("[!] Stored XSS scan error: %v\n", err)
				}
			}
			continue
		}

		if err := scanOneTarget(ctx, engine, scanTarget, allFindings, totalStats); err != nil {
			if errors.Is(err, context.Canceled) {
				color.Yellow("\n[!] Scan cancelled")
				return nil
			}
			color.Yellow("[!] Scan failed for %s: %v — continuing\n", scanURL, err)
		}

		// Auto-discover forms when URL has no query params and no explicit --data.
		if cfg.Body == "" && !hasQueryParams(scanTarget.URL) {
			formTargets := discoverFormsFromPage(ctx, client, scanTarget, cfg.RenderSPA)
			for _, ft := range formTargets {
				if err := scanOneTarget(ctx, engine, ft, allFindings, totalStats); err != nil {
					color.Yellow("[!] Form scan failed for %s: %v\n", ft.URL, err)
				}
			}
		}

		if err := runHeadlessScan(ctx, client, scanTarget, allFindings); err != nil {
			color.Yellow("[!] Headless scan error: %v\n", err)
		}

		if cfg.EnableStored {
			if err := runStoredXSSScan(ctx, client, scanTarget, allFindings); err != nil {
				color.Yellow("[!] Stored XSS scan error: %v\n", err)
			}
		}
	}
	return nil
}

func crawlAndScan(ctx context.Context, client *http.Client, engine *scanner.Engine, scanURL string, baseTarget model.Target, allFindings *[]model.Finding, totalStats *model.ScanStats) error {
	color.Cyan("[*] Crawling %s (depth=%d, maxPages=%d)...\n", scanURL, cfg.CrawlDepth, cfg.CrawlMaxPages)
	crawlCfg := crawler.CrawlerConfig{
		MaxDepth:     cfg.CrawlDepth,
		MaxPages:     cfg.CrawlMaxPages,
		SameHostOnly: true,
		ExtraHeaders: baseTarget.Headers,
	}
	c := crawler.NewCrawlerWithConfig(client, crawlCfg)
	crawlResult, err := c.Crawl(ctx, scanURL)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		color.Yellow("[!] Crawl failed for %s: %v — skipping\n", scanURL, err)
		return nil
	}
	color.Green("[+] Crawl discovered %d URLs, %d forms\n", len(crawlResult.URLs), len(crawlResult.Forms))

	if len(crawlResult.URLs) == 0 && len(crawlResult.Forms) == 0 {
		color.Yellow("[!] Crawl returned no results — target may require authentication or block crawling\n")
	}

	for _, u := range crawlResult.URLs {
		subTarget := deriveTarget(baseTarget, u)
		if err := scanOneTarget(ctx, engine, subTarget, allFindings, totalStats); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			color.Yellow("[!] Scan failed for %s: %v — continuing\n", u, err)
		}
	}

	seenForms := make(map[string]bool)
	for _, form := range crawlResult.Forms {
		formKey := form.Action + "|" + form.Method
		if seenForms[formKey] {
			continue
		}
		seenForms[formKey] = true

		ft := formToTarget(baseTarget, form)
		if err := scanOneTarget(ctx, engine, ft, allFindings, totalStats); err != nil {
			color.Yellow("[!] Form scan failed for %s: %v\n", form.Action, err)
		}
	}
	return nil
}

func discoverFormsFromPage(ctx context.Context, client *http.Client, tgt model.Target, renderSPA bool) []model.Target {
	forms, err := crawler.ExtractFormsFromPage(ctx, client, tgt.URL, tgt.Headers)
	if err != nil {
		color.Yellow("[!] Form auto-discovery skipped: %v\n", err)
		return nil
	}
	if len(forms) == 0 && renderSPA {
		color.Cyan("[*] No static forms found — attempting JS rendering...\n")
		rendered, err := crawler.RenderPage(ctx, tgt.URL, tgt.Headers, 0)
		if err != nil {
			color.Yellow("[!] JS rendering failed: %v\n", err)
			return nil
		}
		forms = rendered.Forms
		if len(forms) > 0 {
			color.Green("[+] JS rendering discovered %d form(s)\n", len(forms))
		}
	}
	if len(forms) == 0 {
		color.Yellow("[!] No HTML forms found on target page\n")
		return nil
	}

	color.Cyan("[*] Discovered %d form(s) on target page\n", len(forms))
	var targets []model.Target
	seen := make(map[string]bool)

	for _, form := range forms {
		formKey := form.Action + "|" + form.Method
		if seen[formKey] {
			continue
		}
		seen[formKey] = true

		ft := formToTarget(tgt, form)
		targets = append(targets, ft)
	}
	return targets
}

func buildFormBody(inputs []string) string {
	vals := make(url.Values, len(inputs))
	for _, name := range inputs {
		vals.Set(name, "test")
	}
	return vals.Encode()
}

func appendQueryParams(rawURL string, inputs []string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	for _, name := range inputs {
		if !q.Has(name) {
			q.Set(name, "test")
		}
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func hasQueryParams(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return parsed.RawQuery != ""
}

func formToTarget(base model.Target, form crawler.FormInfo) model.Target {
	ft := deriveTarget(base, form.Action)
	ft.Method = form.Method
	if form.Method == "POST" {
		ft.Body = buildFormBody(form.Inputs)
		ft.Headers = setContentType(ft.Headers)
	} else {
		ft.URL = appendQueryParams(ft.URL, form.Inputs)
	}
	return ft
}

func setContentType(headers map[string]string) map[string]string {
	if headers == nil {
		headers = make(map[string]string)
	}
	headers[contentTypeHeader] = formURLEncoded
	return headers
}

var ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b`)

func stripANSI(s string) string {
	return ansiEscapeRE.ReplaceAllString(s, "")
}

func collectBlindXSSCallbacks(srv *callback.Server, allFindings *[]model.Finding, callbackURL string, targetURLs []string) {
	if srv.Count() == 0 {
		color.Cyan("[*] Waiting 30s for blind XSS callbacks...")
		srv.WaitFor(1, 30*time.Second)
	}
	cbCount := srv.Count()
	if cbCount > 0 {
		color.Green("\n[+] Received %d blind XSS callback(s):\n", cbCount)
		for i, cb := range srv.Callbacks() {
			color.Green("  [%d] %s %s %s", i+1,
				stripANSI(cb.Method), stripANSI(cb.Path), stripANSI(cb.Query))
			if cb.UserAgent != "" {
				color.Cyan("      UA: %s", stripANSI(cb.UserAgent))
			}
			if cb.Referer != "" {
				color.Cyan("      Referer: %s", stripANSI(cb.Referer))
			}
			if cb.Body != "" {
				color.Cyan("      Body: %s", stripANSI(cb.Body))
			}
		}
		for _, cb := range srv.Callbacks() {
			confidence := 0.9
			desc := fmt.Sprintf("Blind XSS callback received from %s", cb.RemoteAddr)
			// Validate Referer matches a scanned target to prevent callback poisoning.
			// Empty Referer (stripped by Referrer-Policy) is treated as unknown — not spoofed.
			if cb.Referer != "" {
				refererMatch := false
				for _, tu := range targetURLs {
					if ssrfguard.HostsMatch(cb.Referer, tu) {
						refererMatch = true
						break
					}
				}
				if !refererMatch {
					confidence = 0.4
					desc += " (WARNING: Referer does not match any scanned target — may be spoofed)"
					color.Yellow("      [!] Referer does not match any scanned target — marking as low confidence\n")
				}
			}
			*allFindings = append(*allFindings, model.Finding{
				ID:          "BLIND-" + cb.Timestamp.Format("20060102-150405"),
				Type:        model.BlindXSS,
				Severity:    model.High,
				Confidence:  confidence,
				URL:         cb.Referer,
				Parameter:   "blind-xss",
				Payload:     "<script src=\"" + callbackURL + "\"></script>",
				Contexts:    []string{"blind"},
				Description: desc,
				CWE:         "CWE-79",
				Timestamp:   cb.Timestamp,
			})
		}
	} else {
		color.Cyan("[*] No blind XSS callbacks received\n")
	}
	srv.Stop()
}

func reportScanResults(allFindings []model.Finding, totalStats model.ScanStats, urls []string, startTime time.Time) error {
	findingsCount = len(allFindings)
	result := &model.ScanResult{
		Target:   strings.Join(urls, ", "),
		Findings: allFindings,
		Stats:    totalStats,
	}
	duration := time.Since(startTime)
	if !cfg.Silent {
		printResults(result, duration)
	}
	if totalStats.ProbeFiltered > 0 && findingsCount == 0 {
		color.Yellow("[!] %d injection point(s) filtered by --probe — re-run without --probe to confirm\n", totalStats.ProbeFiltered)
	}
	if cfg.Output != "" {
		r := report.NewReporter()
		scanData := report.FromScanResult(result, duration.Milliseconds())
		data, err := r.Generate(scanData, report.OutputFormat(cfg.Format))
		if err != nil {
			return fmt.Errorf("report generation failed: %w", err)
		}
		if err := r.Write(data, cfg.Output); err != nil {
			return fmt.Errorf("report write failed: %w", err)
		}
		color.Green("\n[+] Report saved: %s\n", cfg.Output)
	}
	return nil
}

func buildEngineConfig() scanner.Config {
	return scanner.Config{
		Concurrency:     cfg.Workers,
		RateLimit:       cfg.RateLimit,
		RateBurst:       cfg.RateLimit * 2,
		RequestTimeout:  time.Duration(cfg.Timeout) * time.Second,
		MaxPayloads:     cfg.MaxPayload,
		TestHPP:         cfg.TestHPP,
		WAFBypass:       cfg.WAFBypass,
		ConfidenceMin:   cfg.ConfidenceMin,
		RandomUA:        cfg.RandomUA,
		AdaptiveRate:    cfg.AdaptiveRate,
		EnableProbe:     cfg.EnableProbe,
		VerifyExecution: cfg.VerifyExecution,
		VerifyTimeout:   time.Duration(cfg.VerifyTimeout) * time.Second,
		CSRFToken:       cfg.CSRFToken,
	}
}

func collectChangedFlags(cmd *cobra.Command) map[string]bool {
	changed := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		changed[f.Name] = true
	})
	return changed
}

func validateConfig(cfg *ScanConfig) error {
	// Pipeline mode: no --url and no --targets-file, but stdin is redirected.
	if cfg.URL == "" && cfg.TargetsFile == "" {
		if isStdinPiped() {
			cfg.TargetsFile = "-"
		} else {
			return fmt.Errorf("no target URL provided (use --url, --targets-file, or pipe URLs via stdin)")
		}
	}
	if cfg.Workers > maxWorkers {
		return fmt.Errorf("--workers exceeds maximum allowed (%d)", maxWorkers)
	}
	if cfg.RateLimit < minRateLimit {
		cfg.RateLimit = minRateLimit
	}
	if cfg.Timeout < minTimeout {
		cfg.Timeout = minTimeout
	}
	if cfg.MaxPayload < 0 {
		cfg.MaxPayload = defaultMaxPayload
	}
	// MaxPayload == 0 means unlimited (documented behavior)
	if cfg.LoginURL != "" && cfg.URL != "" {
		if !ssrfguard.HostsMatch(cfg.URL, cfg.LoginURL) {
			return fmt.Errorf("--login-url host must match --url host (got %s vs %s)", cfg.LoginURL, cfg.URL)
		}
	}
	if cfg.EnableStored && len(cfg.TriggerURLs) == 0 {
		return fmt.Errorf("--stored requires at least one --trigger-url")
	}
	return nil
}

// isStdinPiped returns true when stdin is a pipe or redirect (not a TTY).
func isStdinPiped() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

var blockedHeaders = map[string]bool{
	"Host":              true,
	"Content-Length":    true,
	"Transfer-Encoding": true,
}

func parseHeaders(headers []string) map[string]string {
	m := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			if blockedHeaders[key] {
				color.Yellow("[!] Blocked dangerous header: %s\n", key)
				continue
			}
			m[key] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

func parseCookies(cookies []string) []*http.Cookie {
	var result []*http.Cookie
	for _, c := range cookies {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) == 2 {
			result = append(result, &http.Cookie{
				Name:  strings.TrimSpace(parts[0]),
				Value: strings.TrimSpace(parts[1]),
			})
		}
	}
	return result
}

func printBanner() {
	color.Cyan(`
╔═══════════════════════════════════════╗
║   xsscan v%-26s ║
║   For authorized security testing    ║
╚═══════════════════════════════════════╝`, Version)
}

func printResults(result *model.ScanResult, duration time.Duration) {
	fmt.Println()
	color.Cyan("═══ Scan Results ═══")
	fmt.Printf("  Target:    %s\n", result.Target)
	fmt.Printf("  Duration:  %v\n", duration)
	fmt.Printf("  Params:    %d\n", result.Stats.ParametersFound)
	fmt.Printf("  Payloads:  %d\n", result.Stats.PayloadsSent)
	fmt.Printf("  Findings:  %d\n", len(result.Findings))
	fmt.Println()

	if result.Stats.WAF != nil {
		wafColor := color.YellowString
		if result.Stats.WAF.Bypassed {
			wafColor = color.GreenString
		}
		wafStatus := "detected"
		if result.Stats.WAF.Bypassed {
			wafStatus = "detected (bypassed)"
		}
		wafName := result.Stats.WAF.Name
		if wafName == "" {
			wafName = "unknown"
		}
		wafColor("  🛡️  WAF: %s — %s\n", wafName, wafStatus)
	}

	if len(result.Findings) == 0 {
		color.Green("  ✅ No XSS vulnerabilities found\n")
		return
	}

	for i, f := range result.Findings {
		severityColor := getSeverityColor(f.Severity)
		severityColor(fmt.Sprintf("  [%d] [%s] %s", i+1, strings.ToUpper(string(f.Severity)), f.Description))
		fmt.Println()
		fmt.Printf("      Param: %s | Confidence: %.0f%% | Context: %v\n",
			f.Parameter, f.Confidence*100, f.Contexts)
		fmt.Printf("      Payload: %s\n\n", f.Payload)
	}
}

func getSeverityColor(s model.Severity) func(a ...interface{}) string {
	var fn func(format string, a ...interface{}) string
	switch s {
	case model.Critical, model.High:
		fn = color.RedString
	case model.Medium:
		fn = color.YellowString
	case model.Low:
		fn = color.BlueString
	default:
		fn = color.WhiteString
	}
	return func(a ...interface{}) string {
		if len(a) == 0 {
			return ""
		}
		if s, ok := a[0].(string); ok {
			return fn(s, a[1:]...)
		}
		return fn("%v", a...)
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func cloneHeaders(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneCookies(src []*http.Cookie) []*http.Cookie {
	if src == nil {
		return nil
	}
	dst := make([]*http.Cookie, len(src))
	for i, c := range src {
		if c != nil {
			cp := *c
			dst[i] = &cp
		}
	}
	return dst
}

func loadTargets(source string) ([]string, error) {
	var r io.Reader
	if source == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(source)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	var urls []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	return urls, scanner.Err()
}

func scanOneTarget(ctx context.Context, engine *scanner.Engine, tgt model.Target, allFindings *[]model.Finding, totalStats *model.ScanStats) error {
	result, err := engine.Run(ctx, tgt)
	if err != nil {
		return err
	}
	*allFindings = append(*allFindings, result.Findings...)
	totalStats.PayloadsSent += result.Stats.PayloadsSent
	totalStats.ParametersFound += result.Stats.ParametersFound
	totalStats.ProbeFiltered += result.Stats.ProbeFiltered
	if result.Stats.WAF != nil {
		if totalStats.WAF == nil {
			totalStats.WAF = result.Stats.WAF
		} else if result.Stats.WAF.Bypassed {
			totalStats.WAF.Bypassed = true
		}
	}
	return nil
}

func createDOMScanner(ctx context.Context, authState *dom.AuthState, tgt model.Target) (*dom.Scanner, error) {
	if authState != nil {
		scanner, err := dom.NewScannerWithAuth(ctx, 30*time.Second, authState)
		if err != nil {
			return nil, err
		}
		if err := scanner.ApplyAuthState(ctx, tgt.URL); err != nil {
			return nil, fmt.Errorf("apply auth state: %w", err)
		}
		return scanner, nil
	}
	return dom.NewScanner(ctx, 30*time.Second)
}

func runHeadlessScan(ctx context.Context, client *http.Client, tgt model.Target, allFindings *[]model.Finding) error {
	if !cfg.Headless {
		return nil
	}

	color.Cyan("[*] Starting headless DOM XSS scan for %s...\n", tgt.URL)

	var authState *dom.AuthState
	if client.Jar != nil {
		if parsedURL, parseErr := url.Parse(tgt.URL); parseErr == nil {
			jarCookies := client.Jar.Cookies(parsedURL)
			if len(jarCookies) > 0 || len(tgt.Cookies) > 0 {
				authState = &dom.AuthState{
					Cookies: append(jarCookies, tgt.Cookies...),
				}
			}
		}
	}

	domScanner, err := createDOMScanner(ctx, authState, tgt)
	if err != nil {
		color.Yellow("[!] Failed to initialize headless browser: %v — skipping DOM scan\n", err)
		return nil
	}
	defer domScanner.Close()

	payloads := []string{
		`<img src=x onerror=alert(1)>`,
		`<script>alert(1)</script>`,
		`javascript:alert(1)`,
		`'-alert(1)-'`,
		`"><svg onload=alert(1)>`,
	}

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		findings, err := domScanner.DetectDOMXSS(ctx, tgt, payload)
		if err != nil {
			color.Yellow("[!] DOM scan error for payload %s: %v\n", truncateStr(payload, 30), err)
			continue
		}
		*allFindings = append(*allFindings, findings...)
	}

	return nil
}

func runStoredXSSScan(ctx context.Context, client *http.Client, tgt model.Target, allFindings *[]model.Finding) error {
	if !cfg.EnableStored {
		return nil
	}

	color.Cyan("[*] Starting stored XSS detection for %s...\n", tgt.URL)
	color.Cyan("[*] Trigger URL(s): %s\n", strings.Join(cfg.TriggerURLs, ", "))

	params := analyze.ExtractParameters(tgt, cfg.DiscoverHeaders)
	if len(params) == 0 {
		color.Yellow("[!] No injectable parameters found for stored XSS testing\n")
		return nil
	}

	color.Cyan("[*] Found %d injectable parameter(s) for stored XSS testing\n", len(params))

	injections := make([]stored.Injection, 0, len(params))
	for _, param := range params {
		injections = append(injections, stored.Injection{
			Target:    tgt,
			Parameter: param,
			Marker:    analyze.GenerateMarker(),
		})
	}

	storedScanner := stored.NewScanner(client, stored.Config{
		TriggerURLs:     cfg.TriggerURLs,
		PollingInterval: time.Duration(cfg.StoredPollInterval) * time.Second,
		MaxPolls:        cfg.StoredMaxPolls,
		RequestTimeout:  time.Duration(cfg.Timeout) * time.Second,
		Concurrency:     cfg.Workers,
	}, nil)

	findings := storedScanner.Detect(ctx, injections)
	if len(findings) > 0 {
		*allFindings = append(*allFindings, findings...)
		color.Green("[+] Stored XSS: found %d vulnerability(ies)\n", len(findings))
	} else {
		color.Cyan("[*] Stored XSS: no vulnerabilities detected\n")
	}

	return nil
}
