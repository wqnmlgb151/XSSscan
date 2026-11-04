package orchestrator

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestDiscoveryPOSTFormsAndExplicitCrawl(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var foreignHits atomic.Int32
	foreign := testenv.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreignHits.Add(1) }))
	defer foreign.Close()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<form method="post" action="/save"><input name="comment"></form><form action="%s"><input name="secret"></form><a href="/other?q=x">other</a>`, foreign.URL)
	}))
	defer server.Close()
	d := Discoverer{Client: httpclient.NewClient(time.Second, nil), Config: DiscoveryConfig{AllowFormSubmit: true}}
	targets, issues := d.Expand(context.Background(), model.Target{URL: server.URL, Headers: map[string]string{"Authorization": "Bearer fixture"}})
	if len(issues) > 0 || len(targets) != 2 || targets[1].Method != "POST" || targets[1].Body != "comment=test" || targets[1].Headers["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Fatalf("discovery: %+v %+v", targets, issues)
	}
	if foreignHits.Load() != 0 {
		t.Fatal("cross-origin discovery")
	}
}
