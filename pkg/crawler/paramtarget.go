package crawler

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// ParamTarget is a page URL plus the query parameter names found in links
// pointing at it. Used to discover injectable parameters that appear only
// in <a href="...?param=value"> navigation links (dalfox's Grep feature).
type ParamTarget struct {
	URL    string
	Params []string
}

// maxParamTargets bounds the number of discovered targets to prevent
// link-heavy pages from exploding the scan surface.
const maxParamTargets = 20

// extractParamTargets parses HTML and finds same-host links whose query
// strings contain parameter names.
func extractParamTargets(body, pageURL string) []ParamTarget {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	// Map base URL (no query) → set of param names
	paramsByBase := make(map[string]map[string]bool)

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
				collectParams(base, rawURL, paramsByBase)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	// Also mine inline JS for URL strings with query params (dalfox Grep)
	for _, u := range jsURLPattern.FindAllString(body, -1) {
		collectParams(base, strings.Trim(u, `"' `), paramsByBase)
	}

	return buildParamTargets(paramsByBase)
}

// jsURLPattern finds URL-like strings in JS with a query string that has
// at least one key=value pair (avoids matching prose like "why?what").
var jsURLPattern = regexp.MustCompile(`["']([^"']*\?[^"']*=[^"']*)["']`)

// collectParams extracts parameter names from a link's query string if the
// link points at the same host (or is relative).
func collectParams(base *url.URL, rawURL string, paramsByBase map[string]map[string]bool) {
	ref, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return
	}
	resolved := base.ResolveReference(ref)
	if resolved.Hostname() != base.Hostname() {
		return // only same-host targets (port-insensitive)
	}
	if resolved.RawQuery == "" {
		return
	}
	key := resolved.Scheme + "://" + resolved.Host + resolved.Path
	if paramsByBase[key] == nil {
		paramsByBase[key] = make(map[string]bool)
	}
	for _, pair := range strings.Split(resolved.RawQuery, "&") {
		name := pair
		if idx := strings.Index(pair, "="); idx >= 0 {
			name = pair[:idx]
		}
		if name != "" {
			paramsByBase[key][name] = true
		}
	}
}

// buildParamTargets converts the dedup map into a sorted, bounded slice.
func buildParamTargets(paramsByBase map[string]map[string]bool) []ParamTarget {
	targets := make([]ParamTarget, 0, len(paramsByBase))
	for key, params := range paramsByBase {
		names := make([]string, 0, len(params))
		for name := range params {
			names = append(names, name)
		}
		sort.Strings(names)
		targets = append(targets, ParamTarget{URL: key, Params: names})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].URL < targets[j].URL })
	if len(targets) > maxParamTargets {
		targets = targets[:maxParamTargets]
	}
	return targets
}
