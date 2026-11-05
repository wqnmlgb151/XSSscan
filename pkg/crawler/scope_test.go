package crawler

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/pkg/httpclient"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestAutomaticDiscoveryStaysInOrigin(t *testing.T) {

	var foreignHits atomic.Int32
	foreign := testenv.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreignHits.Add(1) }))
	defer foreign.Close()
	origin := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<form action="/local"><input name="q"></form><form action="%s/foreign"><input name="secret"></form><a href="%s/page?q=x">foreign</a><a href="/local?q=x">local</a>`, foreign.URL, foreign.URL)
	}))
	defer origin.Close()
	client := httpclient.NewClient(0, nil, ssrfguard.Policy{AllowPrivate: true})
	defer client.CloseIdleConnections()
	info, err := ExtractPageInfo(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), client, origin.URL, map[string]string{"Authorization": "Bearer exact", "Cookie": "session=exact"})
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Forms) != 1 || !ssrfguard.SameOrigin(origin.URL, info.Forms[0].Action) {
		t.Fatalf("forms: %+v", info.Forms)
	}
	crawler := NewCrawlerWithConfig(client, CrawlerConfig{MaxDepth: 2, MaxPages: 10, SameHostOnly: true, ExtraHeaders: map[string]string{"Authorization": "Bearer exact"}})
	result, err := crawler.Crawl(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range result.URLs {
		if !ssrfguard.SameOrigin(origin.URL, u) {
			t.Errorf("out-of-scope discovery: %s", u)
		}
	}
	if foreignHits.Load() != 0 {
		t.Fatal("foreign origin was contacted")
	}
}

func TestDiscoveryRejectsSchemeAndPortChanges(t *testing.T) {
	body := `<form action="https://example.test:80/a"><input name="x"></form><form action="http://example.test:81/a"><input name="x"></form><form action="javascript:alert(1)"><input name="x"></form><a href="https://example.test:80/a?q=x">x</a><a href="http://example.test:81/a?q=x">x</a>`
	forms, err := extractForms(body, "http://example.test:80/")
	if err != nil || len(forms) != 0 {
		t.Fatalf("forms=%v err=%v", forms, err)
	}
	if got := extractParamTargets(body, "http://example.test:80/"); len(got) != 0 {
		t.Fatalf("param targets: %v", got)
	}
}

func TestDiscoveryAcceptsEquivalentOrigin(t *testing.T) {
	links, err := extractLinks(`<a href="http://EXAMPLE.test:80/path">ok</a>`, "http://example.test/", "example.test", true)
	if err != nil || len(links) != 1 {
		t.Fatalf("links=%v err=%v", links, err)
	}
}

func TestDiscoveryGuardsCallerClientRedirects(t *testing.T) {

	var hits atomic.Int32
	foreign := testenv.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer foreign.Close()
	origin := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, foreign.URL, http.StatusFound) }))
	defer origin.Close()
	_, err := ExtractPageInfo(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), origin.Client(), origin.URL, map[string]string{"Authorization": "Bearer exact"})
	if err == nil || hits.Load() != 0 {
		t.Fatalf("cross-origin discovery redirect: err=%v hits=%d", err, hits.Load())
	}
}
