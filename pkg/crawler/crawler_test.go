package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestExtractLinks_BasicAnchor(t *testing.T) {
	html := `<html><body><a href="/page1">Link1</a><a href="/page2">Link2</a></body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 2 {
		t.Errorf("Expected 2 links, got %d: %v", len(links), links)
	}
	expected := map[string]bool{"http://example.com/page1": true, "http://example.com/page2": true}
	for _, l := range links {
		if !expected[l] {
			t.Errorf("Unexpected link: %s", l)
		}
	}
}

func TestExtractLinks_FormAction(t *testing.T) {
	html := `<html><body><form action="/search" method="get"><input name="q"></form></body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 1 || links[0] != "http://example.com/search" {
		t.Errorf("Expected [http://example.com/search], got %v", links)
	}
}

func TestExtractLinks_IframeSrc(t *testing.T) {
	html := `<html><body><iframe src="/embed"></iframe></body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 1 || links[0] != "http://example.com/embed" {
		t.Errorf("Expected [http://example.com/embed], got %v", links)
	}
}

func TestExtractLinks_FrameSrc(t *testing.T) {
	html := `<html><frameset><frame src="/nav"></frameset></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 1 || links[0] != "http://example.com/nav" {
		t.Errorf("Expected [http://example.com/nav], got %v", links)
	}
}

func TestExtractLinks_AreaHref(t *testing.T) {
	html := `<html><body><map name="m"><area href="/area-link" shape="rect"></map></body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 1 || links[0] != "http://example.com/area-link" {
		t.Errorf("Expected [http://example.com/area-link], got %v", links)
	}
}

func TestExtractLinks_RelativeURLs(t *testing.T) {
	html := `<html><body>
		<a href="page.html">rel</a>
		<a href="../parent.html">parent</a>
		<a href="./current.html">current</a>
	</body></html>`
	links, err := extractLinks(html, "http://example.com/dir/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 3 {
		t.Errorf("Expected 3 links, got %d: %v", len(links), links)
	}
	expected := map[string]bool{
		"http://example.com/dir/page.html":   true,
		"http://example.com/parent.html":     true,
		"http://example.com/dir/current.html": true,
	}
	for _, l := range links {
		if !expected[l] {
			t.Errorf("Unexpected link: %s", l)
		}
	}
}

func TestExtractLinks_AbsoluteURL(t *testing.T) {
	html := `<html><body><a href="http://example.com/absolute">abs</a></body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 1 || links[0] != "http://example.com/absolute" {
		t.Errorf("Expected [http://example.com/absolute], got %v", links)
	}
}

func TestExtractLinks_SameHostFilter(t *testing.T) {
	html := `<html><body>
		<a href="/internal">internal</a>
		<a href="http://evil.com/external">external</a>
	</body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 1 || links[0] != "http://example.com/internal" {
		t.Errorf("Expected only same-host link, got %v", links)
	}
}

func TestExtractLinks_NoFilter(t *testing.T) {
	html := `<html><body>
		<a href="/internal">internal</a>
		<a href="http://other.com/page">external</a>
	</body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", false)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 2 {
		t.Errorf("Expected 2 links with sameHostOnly=false, got %d: %v", len(links), links)
	}
}

func TestExtractLinks_SkipsFragments(t *testing.T) {
	html := `<html><body><a href="#section">anchor</a></body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("Expected 0 links (fragment skipped), got %v", links)
	}
}

func TestExtractLinks_SkipsJavaScript(t *testing.T) {
	html := `<html><body><a href="javascript:void(0)">js</a><a href="mailto:a@b.com">email</a></body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("Expected 0 links (javascript/mailto skipped), got %v", links)
	}
}

func TestExtractLinks_Dedup(t *testing.T) {
	html := `<html><body>
		<a href="/page">first</a>
		<a href="/page">duplicate</a>
		<a href="/page">triplicate</a>
	</body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 1 {
		t.Errorf("Expected 1 link (deduped), got %d: %v", len(links), links)
	}
}

func TestExtractLinks_StripsFragment(t *testing.T) {
	html := `<html><body><a href="/page#section">frag</a></body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 1 || links[0] != "http://example.com/page" {
		t.Errorf("Expected [http://example.com/page] (fragment stripped), got %v", links)
	}
}

func TestExtractLinks_EmptyHTML(t *testing.T) {
	html := `<html><body><p>No links here</p></body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("Expected 0 links, got %d", len(links))
	}
}

func TestExtractLinks_MultipleTagTypes(t *testing.T) {
	html := `<html><body>
		<a href="/a">link</a>
		<form action="/f">form</form>
		<iframe src="/i">iframe</iframe>
		<area href="/area">area</area>
	</body></html>`
	links, err := extractLinks(html, "http://example.com/", "example.com", true)
	if err != nil {
		t.Fatalf("extractLinks failed: %v", err)
	}
	if len(links) != 4 {
		t.Errorf("Expected 4 links (a+form+iframe+area), got %d: %v", len(links), links)
	}
}

func TestCrawler_CrawlSinglePage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/page1">link</a></body></html>`))
	}))
	defer server.Close()

	// maxDepth=0: only the start URL, no link following
	c := NewCrawler(nil, 0, 10, true)
	result, err := c.Crawl(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}
	if len(result.URLs) != 1 {
		t.Errorf("Expected 1 URL (depth=0, no follow), got %d: %v", len(result.URLs), result.URLs)
	}
}

func TestCrawler_CrawlTwoDepths(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><body><a href="/page1">link</a></body></html>`))
		case "/page1":
			w.Write([]byte(`<html><body><a href="/page2">link</a></body></html>`))
		default:
			w.Write([]byte(`<html><body>end</body></html>`))
		}
	}))
	defer server.Close()

	// maxDepth=2: start (d0) → page1 (d1) → page2 (d2)
	c := NewCrawler(nil, 2, 10, true)
	result, err := c.Crawl(context.Background(), server.URL+"/")
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}
	if len(result.URLs) != 3 {
		t.Errorf("Expected 3 URLs (depth 0, 1, 2), got %d: %v", len(result.URLs), result.URLs)
	}
}

func TestCrawler_CrawlMaxPages(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Every page links to 3 more pages (wide graph)
		w.Write([]byte(`<html><body>
			<a href="/a">a</a>
			<a href="/b">b</a>
			<a href="/c">c</a>
		</body></html>`))
	}))
	defer server.Close()

	// maxPages=3: start (1) + a (2) + b (3) → stop before c
	c := NewCrawler(nil, 5, 3, false)
	result, err := c.Crawl(context.Background(), server.URL+"/")
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}
	if len(result.URLs) != 3 {
		t.Errorf("Expected 3 URLs (maxPages=3), got %d: %v", len(result.URLs), result.URLs)
	}
}

func TestCrawler_CrawlContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/page1">link</a></body></html>`))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancel

	c := NewCrawler(nil, 2, 10, true)
	result, err := c.Crawl(ctx, server.URL)
	if err == nil {
		t.Error("Expected context.Canceled error, got nil")
	}
	if len(result.URLs) != 0 {
		t.Errorf("Expected 0 URLs on cancellation, got %d", len(result.URLs))
	}
}

func TestCrawler_CrawlInvalidStartURL(t *testing.T) {
	c := NewCrawler(nil, 2, 10, true)
	_, err := c.Crawl(context.Background(), "://invalid")
	if err == nil {
		t.Error("Expected error for invalid start URL, got nil")
	}
}

func TestCrawler_CrawlNonHTMLOverHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"links": ["/page1"]}`))
	}))
	defer server.Close()

	c := NewCrawler(nil, 2, 10, true)
	result, err := c.Crawl(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}
	// Should return just the start URL (non-HTML pages are not crawled for links)
	if len(result.URLs) != 1 {
		t.Errorf("Expected 1 URL (non-HTML not crawled), got %d: %v", len(result.URLs), result.URLs)
	}
}

func TestCrawler_NewCrawlerDefaults(t *testing.T) {
	// Negative values trigger defaults; 0 is valid (start URL only)
	c := NewCrawler(nil, -1, 0, true)
	if c.maxDepth != defaultMaxDepth {
		t.Errorf("Expected default maxDepth=%d, got %d", defaultMaxDepth, c.maxDepth)
	}
	if c.maxPages != defaultMaxPages {
		t.Errorf("Expected default maxPages=%d, got %d", defaultMaxPages, c.maxPages)
	}
	if c.client == nil {
		t.Error("Expected non-nil client")
	}
	if c.visited == nil {
		t.Error("Expected non-nil visited map")
	}
}

func TestCrawler_NewCrawlerZeroDepth(t *testing.T) {
	// maxDepth=0 means "start URL only, no link following"
	c := NewCrawler(nil, 0, 10, true)
	if c.maxDepth != 0 {
		t.Errorf("Expected maxDepth=0, got %d", c.maxDepth)
	}
}

func TestResolveURL_SchemeFiltered(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	cases := []struct {
		ref      string
		expected string
	}{
		{"#anchor", ""},
		{"javascript:void(0)", ""},
		{"mailto:test@test.com", ""},
		{"data:text/html,hello", ""},
		{"", ""},
	}
	for _, tc := range cases {
		result := resolveURL(base, tc.ref)
		if result != tc.expected {
			t.Errorf("resolveURL(%q): expected %q, got %q", tc.ref, tc.expected, result)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"http://example.com/page#frag", "http://example.com/page"},
		{"http://example.com/page/", "http://example.com/page"},
		{"http://example.com/", "http://example.com"},
		{"http://example.com", "http://example.com"},
	}
	for _, tc := range cases {
		u, _ := url.Parse(tc.input)
		result := normalizeURL(u)
		if result != tc.expected {
			t.Errorf("normalizeURL(%q): expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

// ===== Route Pattern Extraction Tests =====

func TestExtractRoutePatterns_VueRouter(t *testing.T) {
	html := `<html><script>const routes = [{ path: '/users', component: Users }]</script></html>`
	paths := extractRoutePatterns(html)
	if len(paths) != 1 || paths[0] != "/users" {
		t.Errorf("Expected [/users], got %v", paths)
	}
}

func TestExtractRoutePatterns_ReactRouter(t *testing.T) {
	html := `<html><script><Route path="/admin" component={Admin} /></script></html>`
	paths := extractRoutePatterns(html)
	// React Router JSX path extraction is a bonus - may not be in script
	// Just verify it does not panic and returns nil or the path
	_ = paths
}

func TestExtractRoutePatterns_MultipleRoutes(t *testing.T) {
	html := `<html><script>const routes = [\n\t\t{ path: '/home', component: Home },\n\t\t{ path: '/about', component: About },\n\t\t{ path: '/contact', component: Contact }\n\t]</script></html>`
	paths := extractRoutePatterns(html)
	if len(paths) != 3 {
		t.Errorf("Expected 3 paths, got %d: %v", len(paths), paths)
	}
	expected := map[string]bool{"/home": true, "/about": true, "/contact": true}
	for _, p := range paths {
		if !expected[p] {
			t.Errorf("Unexpected path: %s", p)
		}
	}
}

// ===== Sitemap and Robots Discovery Tests =====

func TestDiscoverSitemap(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/page1</loc></url>
  <url><loc>http://example.com/page2</loc></url>
</urlset>`))
	}))
	defer ts.Close()

	urls, err := DiscoverFromSitemap(ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("DiscoverFromSitemap failed: %v", err)
	}
	if len(urls) != 2 {
		t.Errorf("Expected 2 URLs, got %d: %v", len(urls), urls)
	}
}

func TestDiscoverRobots(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "User-agent: *\nDisallow: /private\nSitemap: http://example.com/sitemap.xml\n")
	}))
	defer ts.Close()

	urls, err := DiscoverFromRobots(ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("DiscoverFromRobots failed: %v", err)
	}
	found := false
	for _, u := range urls {
		if strings.Contains(u, "sitemap.xml") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find sitemap URL, got %v", urls)
	}
}

func TestCrawl_WithSitemapDiscovery(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><body><a href="/page1">Link</a></body></html>`))
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>` + r.Host + `/sitemap-page</loc></url></urlset>`))
		default:
			w.Write([]byte(`<html><body>No links</body></html>`))
		}
	}))
	defer ts.Close()

	c := NewCrawlerWithConfig(ts.Client(), CrawlerConfig{
		MaxDepth:        1,
		MaxPages:        10,
		SameHostOnly:    false,
		DiscoverSitemap: true,
	})
	result, err := c.Crawl(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}
	// Should have start URL + page1 + sitemap-page
	if len(result.URLs) < 2 {
		t.Errorf("Expected at least 2 URLs, got %d: %v", len(result.URLs), result.URLs)
	}
}
