package orchestrator

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
	"github.com/wqnmlgb151/XSSscan/pkg/browser"
	"github.com/wqnmlgb151/XSSscan/pkg/dom"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/pkg/stored"
)

// DOMModule keeps browser creation and detector lifecycle out of CLI parsing.
// DOMModule builds the DOM detection module.
//
// replayOriginal controls whether each DOM candidate is additionally confirmed with its
// unmarked payload in a fresh browser context. It costs a second page load per test, so
// it follows the execution-verification setting rather than being unconditional.
func DOMModule(client *http.Client, timeout time.Duration, replayOriginal bool) Module {
	return Module{Type: DOM, Check: func(ctx context.Context, target model.Target) error {
		if err := ssrfguard.IsURLTargetAllowedContext(ctx, target.URL); err != nil {
			return err
		}
		return browser.EnsureChrome()
	}, Run: func(ctx context.Context, target model.Target) (*model.ScanResult, error) {
		result := &model.ScanResult{Target: target.URL}
		auth := &dom.AuthState{}
		if client.Jar != nil {
			if u, err := url.Parse(target.URL); err == nil {
				auth.Cookies = client.Jar.Cookies(u)
			}
		}
		detector, err := dom.NewScannerWithAuth(ctx, timeout, auth)
		if err != nil {
			return result, err
		}
		defer detector.Close()
		detector.SetOriginalReplay(replayOriginal)
		if err := detector.CheckTarget(ctx, target); err != nil {
			return result, err
		}
		probes := []string{`<img src=x onerror=alert(1)>`, `<script>alert(1)</script>`, `javascript:alert(1)`, `'-alert(1)-'`, `"><svg onload=alert(1)>`}
		var coverage model.CheckCoverage
		result.Findings, coverage, err = detector.DetectPayloadsWithCoverage(ctx, target, probes)
		result.Stats.Coverage = []model.CheckCoverage{coverage}
		result.Stats.PayloadsSent = len(probes)
		return result, err
	}}
}

func StoredModule(client *http.Client, config stored.Config, discoverHeaders bool) Module {
	return Module{Type: Stored, Check: func(_ context.Context, target model.Target) error {
		if len(analyze.ExtractParameters(target, discoverHeaders)) == 0 {
			return fmt.Errorf("no injectable parameters for stored detection")
		}
		return nil
	}, Run: func(ctx context.Context, target model.Target) (*model.ScanResult, error) {
		result := &model.ScanResult{Target: target.URL}
		params := analyze.ExtractParameters(target, discoverHeaders)
		result.Stats.ParametersFound = len(params)
		injections := make([]stored.Injection, 0, len(params))
		for _, param := range params {
			injections = append(injections, stored.Injection{Target: target, Parameter: param, Marker: analyze.GenerateMarkerContext(ctx)})
		}
		detector := stored.NewScanner(client, config, nil)
		findings, err := detector.DetectWithError(ctx, injections)
		result.Findings = findings
		result.Stats.PayloadsSent = detector.SubmissionCount()
		return result, err
	}}
}
