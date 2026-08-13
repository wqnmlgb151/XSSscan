// Package urlutil provides URL normalization helpers with distinct,
// explicit semantics so callers never confuse dedup and crawl normalization.
package urlutil

import (
	"net/url"
	"strings"
)

// NormalizeForDedup strips query and fragment for finding-dedup keys.
// Payload-specific query strings must not create unique keys per payload.
func NormalizeForDedup(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.ForceQuery = false
	u.RawFragment = ""
	return u.String()
}

// NormalizeForCrawl canonicalizes a URL for the crawl visited-set:
// strips default ports (80/443), fragment, and trailing slash.
// Query is KEPT — /page?a=1 and /page?a=2 are different crawl targets.
func NormalizeForCrawl(u *url.URL) string {
	if u == nil {
		return ""
	}
	clone := *u
	if (clone.Scheme == "http" && clone.Port() == "80") ||
		(clone.Scheme == "https" && clone.Port() == "443") {
		clone.Host = clone.Hostname()
	}
	clone.Fragment = ""
	clone.RawFragment = ""
	// Strip trailing slashes including the root path (matches original
	// crawler behavior: "http://example.com/" → "http://example.com").
	clone.Path = strings.TrimRight(clone.Path, "/")
	return clone.String()
}
