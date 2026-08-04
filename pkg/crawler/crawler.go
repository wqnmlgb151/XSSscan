// Package crawler provides lightweight same-host link discovery for XSS scanning.
// It extracts links from HTML responses (a, form, area, frame, iframe) and
// returns a deduplicated list of URLs reachable within a configurable depth.
// Enhanced in v0.9.0 with SPA route discovery and sitemap/robots.txt support.
package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"golang.org/x/net/html"
)

const (
	defaultMaxDepth    = 2
	defaultMaxPages    = 50
	parallelWorkers    = 10
)

// Crawler performs breadth-first same-host link discovery.
type Crawler struct {
	client          *http.Client
	maxDepth        int
	maxPages        int
	sameHostOnly    bool
	discoverSitemap bool
	discoverRobots  bool
	extraHeaders    map[string]string
	visited         map[string]bool
	mu              sync.Mutex
}

// FormInfo represents a discovered HTML form with its input fields.
// Action is the resolved absolute URL. Method is GET or POST.
// Inputs contains the name attributes of text/password/email/search/url/tel/number/date
// inputs, plus select and textarea fields. Hidden fields are included too
// since they often carry CSRF tokens or preset values.
type FormInfo struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
}

// CrawlResult holds the discovered URLs and forms.
type CrawlResult struct {
	URLs  []string   `json:"urls"`
	Forms []FormInfo `json:"forms,omitempty"`
}

// CrawlerConfig holds configuration for the crawler.
type CrawlerConfig struct {
	MaxDepth        int
	MaxPages        int
	SameHostOnly    bool
	DiscoverSitemap bool
	DiscoverRobots  bool
	ExtraHeaders    map[string]string
}

// NewCrawler creates a crawler with the given options.
// If client is nil, a default HTTP client is used.
func NewCrawler(client *http.Client, maxDepth, maxPages int, sameHostOnly bool) *Crawler {
	return NewCrawlerWithConfig(client, CrawlerConfig{
		MaxDepth:     maxDepth,
		MaxPages:     maxPages,
		SameHostOnly: sameHostOnly,
	})
}

// NewCrawlerWithConfig creates a crawler using a configuration struct.
func NewCrawlerWithConfig(client *http.Client, config CrawlerConfig) *Crawler {
	if client == nil {
		client = httpclient.NewClient(30*time.Second, nil)
	}
	if config.MaxDepth < 0 {
		config.MaxDepth = defaultMaxDepth
	}
	if config.MaxPages <= 0 {
		config.MaxPages = defaultMaxPages
	}
	return &Crawler{
		client:          client,
		maxDepth:        config.MaxDepth,
		maxPages:        config.MaxPages,
		sameHostOnly:    config.SameHostOnly,
		discoverSitemap: config.DiscoverSitemap,
		discoverRobots:  config.DiscoverRobots,
		extraHeaders:    config.ExtraHeaders,
		visited:         make(map[string]bool),
	}
}

// Crawl starts breadth-first discovery from startURL, returning all unique URLs found.
//
// URLs at the same depth are fetched concurrently using a worker pool
// (parallelWorkers goroutines), giving roughly N× speedup per depth level
// where N is the worker count. Shared state (visited map, result slice) is
// protected by the existing mutex on isVisited/markVisited and by the
// single-threaded collection phase between depth levels.
func (c *Crawler) Crawl(ctx context.Context, startURL string) (*CrawlResult, error) {
	start, err := url.Parse(startURL)
	if err != nil {
		return nil, fmt.Errorf("invalid start URL: %w", err)
	}
	startHost := start.Host

	// Run sitemap/robots discovery before BFS crawl if enabled.
	discoveryURLs := c.discoverSeeds(ctx, startURL)

	var resultURLs []string
	var resultForms []FormInfo
	pageCount := 0

	// currentLevel holds URLs at the current depth to process serially
	// (visited filtering, maxPages enforcement) before parallel fetch.
	currentLevel := []string{startURL}

	for depth := 0; depth <= c.maxDepth && len(currentLevel) > 0; depth++ {
		select {
		case <-ctx.Done():
			return &CrawlResult{URLs: resultURLs, Forms: resultForms}, ctx.Err()
		default:
		}

		// Phase 1 — serial: filter visited, enforce maxPages, collect toProcess.
		var toProcess []string
		for _, u := range currentLevel {
			if c.isVisited(u) {
				continue
			}
			c.markVisited(u)
			resultURLs = append(resultURLs, u)
			toProcess = append(toProcess, u)
			pageCount++
			if pageCount >= c.maxPages {
				break
			}
		}

		if pageCount >= c.maxPages {
			break
		}

		// If we've reached max depth, don't fetch links.
		if depth >= c.maxDepth {
			break
		}

		// Phase 2 — parallel: fetch and extract links + forms for all URLs at this depth.
		allLinks, allForms := c.fetchLevelParallel(ctx, toProcess, startHost)
		resultForms = append(resultForms, allForms...)

		// Phase 3 — serial: collect next level with deduplication.
		nextLevelSeen := make(map[string]bool)
		var nextLevel []string
		for _, link := range allLinks {
			if c.isVisited(link) || nextLevelSeen[link] {
				continue
			}
			nextLevelSeen[link] = true
			nextLevel = append(nextLevel, link)
		}

		// Merge discovery seeds after depth 0 (they start at depth 1).
		if depth == 0 {
			for _, du := range discoveryURLs {
				if !c.isVisited(du) && !nextLevelSeen[du] {
					nextLevelSeen[du] = true
					nextLevel = append(nextLevel, du)
				}
			}
		}

		currentLevel = nextLevel
	}

	return &CrawlResult{URLs: resultURLs, Forms: resultForms}, nil
}

// fetchLevelParallel fetches and extracts links and forms from all URLs
// concurrently using a bounded worker pool. Returns the union of all
// discovered links and forms.
func (c *Crawler) fetchLevelParallel(ctx context.Context, urls []string, startHost string) ([]string, []FormInfo) {
	n := len(urls)
	if n == 0 {
		return nil, nil
	}

	// Adaptive worker count: one goroutine per URL for small levels,
	// capped at parallelWorkers for large levels.
	numWorkers := n
	if numWorkers > parallelWorkers {
		numWorkers = parallelWorkers
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		allLinks []string
		allForms []FormInfo
	)

	workCh := make(chan string, numWorkers)

	// Start workers.
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pageURL := range workCh {
				links, forms, err := c.fetchAndExtract(ctx, pageURL, startHost)
				if err == nil {
					mu.Lock()
					allLinks = append(allLinks, links...)
					allForms = append(allForms, forms...)
					mu.Unlock()
				}
			}
		}()
	}

	// Dispatch work.
	for _, u := range urls {
		workCh <- u
	}
	close(workCh)

	wg.Wait()
	return allLinks, allForms
}

// discoverSeeds runs sitemap.xml and robots.txt discovery concurrently if enabled.
func (c *Crawler) discoverSeeds(ctx context.Context, startURL string) []string {
	type result struct {
		urls []string
	}

	var (
		robotsRes  result
		sitemapRes result
	)

	// Run robots.txt and sitemap.xml discovery concurrently — they are
	// independent network calls and parallelizing cuts seed discovery
	// latency roughly in half when both are enabled.
	var wg sync.WaitGroup

	if c.discoverRobots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls, err := DiscoverFromRobotsContext(ctx, c.client, startURL)
			if err == nil {
				robotsRes.urls = urls
			}
		}()
	}

	if c.discoverSitemap {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls, err := DiscoverFromSitemapContext(ctx, c.client, startURL)
			if err == nil {
				sitemapRes.urls = urls
			}
		}()
	}

	wg.Wait()

	// Merge results preserving order: robots first, then sitemap.
	seen := make(map[string]bool)
	var seeds []string
	for _, u := range robotsRes.urls {
		if !seen[u] {
			seen[u] = true
			seeds = append(seeds, u)
		}
	}
	for _, u := range sitemapRes.urls {
		if !seen[u] {
			seen[u] = true
			seeds = append(seeds, u)
		}
	}

	return seeds
}

// fetchAndExtract retrieves a page and extracts links and forms from it.
func (c *Crawler) fetchAndExtract(ctx context.Context, pageURL, startHost string) ([]string, []FormInfo, error) {
	// SSRF protection: validate URL before fetching. Without this,
	// DNS rebinding could bypass the initial SSRF check on the
	// startURL and make the crawler request internal addresses.
	if err := ssrfguard.IsURLTargetAllowed(pageURL); err != nil {
		return nil, nil, fmt.Errorf("ssrf blocked: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", httpclient.DefaultUA)
	for k, v := range c.extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
		return nil, nil, fmt.Errorf("non-HTML content: %s", ct)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
	if err != nil {
		return nil, nil, err
	}

	bodyStr := string(bodyBytes)

	links, err := extractLinks(bodyStr, pageURL, startHost, c.sameHostOnly)
	if err != nil {
		return nil, nil, err
	}

	forms, err := extractForms(bodyStr, pageURL)
	if err != nil {
		// forms are best-effort; a parse error shouldn't block link extraction
		forms = nil
	}

	return links, forms, nil
}

func (c *Crawler) isVisited(u string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.visited[u]
}

func (c *Crawler) markVisited(u string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.visited[u] = true
}

// extractLinks parses HTML and extracts all navigable URLs.
// Resolves relative URLs against baseURL and optionally filters to same-host only.
// Enhanced in v0.9.0 to extract SPA attributes and JS route patterns.
func extractLinks(body string, baseURL, startHost string, sameHostOnly bool) ([]string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	seen := make(map[string]bool)
	var links []string

	tryAddLink := func(rawURL string) {
		if rawURL == "" {
			return
		}
		resolved := resolveURL(base, rawURL)
		if resolved == "" {
			return
		}
		u, err := url.Parse(resolved)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		if sameHostOnly && u.Host != startHost {
			return
		}
		normalized := normalizeURL(u)
		if !seen[normalized] {
			seen[normalized] = true
			links = append(links, normalized)
		}
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("HTML parse error: %w", err)
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			var rawURL string
			switch n.Data {
			case "a", "area", "link":
				rawURL = getAttr(n, "href")
			case "form":
				rawURL = getAttr(n, "action")
			case "frame", "iframe":
				rawURL = getAttr(n, "src")
			}

			if rawURL != "" {
				tryAddLink(rawURL)
			}

			for _, attr := range n.Attr {
				lowerKey := strings.ToLower(attr.Key)
				switch lowerKey {
				case "ng-href", "[routerlink]", "[router-link]":
					tryAddLink(attr.Val)
				case "data-href", "data-link", "data-url":
					tryAddLink(attr.Val)
				case "to":
					if strings.EqualFold(n.Data, "router-link") {
						tryAddLink(attr.Val)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	// Extract route patterns from JavaScript blocks
	for _, pattern := range extractRoutePatterns(body) {
		tryAddLink(pattern)
	}

	return links, nil
}

// resolveURL resolves href against base, filtering non-http schemes and fragment-only URLs.
func resolveURL(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	// Filter non-http schemes (javascript:, mailto:, data:, etc.)
	if ref.Scheme != "" && ref.Scheme != "http" && ref.Scheme != "https" {
		return ""
	}
	resolved := base.ResolveReference(ref)
	resolved.Fragment = ""
	return resolved.String()
}

// normalizeURL removes default ports, strips fragments and trailing slashes.
// Returns a new string without modifying the input *url.URL.
func normalizeURL(u *url.URL) string {
	clone := *u
	if clone.Scheme == "http" && clone.Port() == "80" {
		clone.Host = clone.Hostname()
	} else if clone.Scheme == "https" && clone.Port() == "443" {
		clone.Host = clone.Hostname()
	}
	clone.Fragment = ""
	clone.Path = strings.TrimRight(clone.Path, "/")
	return clone.String()
}

func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

// ExtractFormsFromPage fetches a URL and extracts HTML forms with their input fields.
// Optional headers (e.g., Authorization, JWT, custom) are applied after User-Agent.
// Returns nil if the page is not HTML or no forms are found.
func ExtractFormsFromPage(ctx context.Context, client *http.Client, pageURL string, headers map[string]string) ([]FormInfo, error) {
	if err := ssrfguard.IsURLTargetAllowed(pageURL); err != nil {
		return nil, fmt.Errorf("ssrf blocked: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpclient.DefaultUA)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("HTTP %d — target requires authentication (use --login-url, --cookie, --header, or --jwt)", resp.StatusCode)
	default:
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
		return nil, fmt.Errorf("non-HTML content: %s", ct)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
	if err != nil {
		return nil, err
	}

	return extractForms(string(bodyBytes), pageURL)
}

// extractForms parses HTML and extracts form details: action URL, method, and input field names.
// Resolves relative action URLs against baseURL. Skips forms with no named inputs.
// Inputs of type submit/button/image/reset are excluded as they carry no scan-relevant data.
func extractForms(body string, baseURL string) ([]FormInfo, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("HTML parse error: %w", err)
	}

	var forms []FormInfo

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			action := getAttr(n, "action")
			method := strings.ToUpper(getAttr(n, "method"))
			if method != "POST" {
				method = "GET"
			}

			// Resolve action URL against base. If empty or resolves to nothing,
			// the form submits to the current page.
			if action != "" {
				if resolved := resolveURL(base, action); resolved != "" {
					action = resolved
				}
			}
			if action == "" {
				action = baseURL
			}

			// Collect named input fields within this form.
			inputs := collectFormInputs(n)
			if len(inputs) > 0 {
				forms = append(forms, FormInfo{
					Action: action,
					Method: method,
					Inputs: inputs,
				})
			}
			// Don't recurse into nested forms (HTML forbids them, but guard anyway).
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	return forms, nil
}

// skipInputTypes lists input types excluded from form auto-discovery.
var skipInputTypes = map[string]bool{"submit": true, "button": true, "image": true, "reset": true}

// collectFormInputs recursively walks a <form> subtree and collects name attributes
// from input (text, password, email, search, url, tel, number, date, hidden),
// select, and textarea elements. Submit/button/image/reset types are excluded.
func collectFormInputs(formNode *html.Node) []string {
	seen := make(map[string]bool)
	var inputs []string

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input":
				name := getAttr(n, "name")
				inputType := strings.ToLower(getAttr(n, "type"))
				if name != "" && !skipInputTypes[inputType] && !seen[name] {
					seen[name] = true
					inputs = append(inputs, name)
				}
			case "select", "textarea":
				name := getAttr(n, "name")
				if name != "" && !seen[name] {
					seen[name] = true
					inputs = append(inputs, name)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(formNode)
	return inputs
}

// extractSPALinks finds links that SPAs embed in HTML but are not standard hrefs.
// Returns relative or absolute path strings (not fully resolved URLs).
//
// Supported patterns:
//   - Angular: ng-href, [routerLink] attributes
//   - Vue: to attribute on <router-link> elements
//   - React/generic: data-href, data-link, data-url attributes
func extractSPALinks(body string, baseURL *url.URL) []string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var links []string

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				lowerKey := strings.ToLower(attr.Key)
				var val string
				switch lowerKey {
				case "ng-href", "[routerlink]", "[router-link]",
					"data-href", "data-link", "data-url":
					val = attr.Val
				case "to":
					if strings.EqualFold(n.Data, "router-link") {
						val = attr.Val
					}
				}
				if val != "" && !seen[val] {
					seen[val] = true
					links = append(links, val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	return links
}

// extractRoutePatterns parses JavaScript blocks for common SPA route definitions.
func extractRoutePatterns(body string) []string {
	var routes []string
	seen := make(map[string]bool)

	// path: '/route' or path: "/route" (Vue Router, React Router)
	routeRe := regexp.MustCompile(`path\s*:\s*['"]([^'"]+)['"]`)
	for _, m := range routeRe.FindAllStringSubmatch(body, -1) {
		path := m[1]
		if strings.HasPrefix(path, "/") && !seen[path] {
			seen[path] = true
			routes = append(routes, path)
		}
	}

	return routes
}



// DiscoverFromRobotsContext fetches /robots.txt and extracts Sitemap directives and Allow paths.
func DiscoverFromRobotsContext(ctx context.Context, client *http.Client, baseURL string) ([]string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	robotsURL := parsed.Scheme + "://" + parsed.Host + "/robots.txt"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("robots.txt not found")
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	var urls []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		var extracted string
		if strings.HasPrefix(lower, "sitemap:") {
			extracted = strings.TrimSpace(line[8:])
		} else if strings.HasPrefix(lower, "allow:") {
			extracted = strings.TrimSpace(line[6:])
		}
		if extracted != "" && !seen[extracted] {
			seen[extracted] = true
			if strings.HasPrefix(extracted, "http") {
				urls = append(urls, extracted)
			} else {
				urls = append(urls, parsed.Scheme+"://"+parsed.Host+extracted)
			}
		}
	}
	return urls, nil
}

// DiscoverFromSitemapContext fetches /sitemap.xml and extracts URLs.
func DiscoverFromSitemapContext(ctx context.Context, client *http.Client, baseURL string) ([]string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	sitemapURL := parsed.Scheme + "://" + parsed.Host + "/sitemap.xml"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sitemapURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sitemap.xml not found")
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	bodyStr := string(body)
	urlRE := regexp.MustCompile(`<loc>\s*(.*?)\s*</loc>`)
	matches := urlRE.FindAllStringSubmatch(bodyStr, -1)

	var urls []string
	seen := make(map[string]bool)
	for _, m := range matches {
		u := strings.TrimSpace(m[1])
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	return urls, nil
}
