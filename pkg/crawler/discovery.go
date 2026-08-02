// Package crawler provides lightweight same-host link discovery for XSS scanning.
// This file contains sitemap.xml and robots.txt discovery functions.
package crawler

import (
	"context"
	"net/http"
)

// DiscoverFromSitemap fetches /sitemap.xml and extracts URLs.
// This is a convenience wrapper that creates a background context.
func DiscoverFromSitemap(client *http.Client, baseURL string) ([]string, error) {
	return DiscoverFromSitemapContext(context.Background(), client, baseURL)
}

// DiscoverFromRobots fetches /robots.txt and extracts Sitemap directives and Allow paths.
// This is a convenience wrapper that creates a background context.
func DiscoverFromRobots(client *http.Client, baseURL string) ([]string, error) {
	return DiscoverFromRobotsContext(context.Background(), client, baseURL)
}
