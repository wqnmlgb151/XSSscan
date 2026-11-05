package integration

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/scanner"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestPathAnalysisToFinding(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.EscapedPath(), "/")
		value, _ := url.PathUnescape(parts[len(parts)-1])
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", value)
	}))
	defer server.Close()
	engine := scanner.NewEngine(scanner.Config{Concurrency: 2, RateLimit: 10000, RateBurst: 10000, MaxPayloads: 10, RequestTimeout: 5 * time.Second}, nil, server.Client())
	target := model.Target{URL: server.URL + "/fixed/a%2Fb/name%21"}
	result, err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if finding.ParamType == model.ParamPath && finding.Parameter == "path[3]" {
			return
		}
	}
	t.Fatalf("path analysis did not reach a finding: %+v", result)
}
