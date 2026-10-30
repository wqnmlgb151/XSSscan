package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/xsscan/xsscan/pkg/blind"
	"github.com/xsscan/xsscan/pkg/callback"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/orchestrator"
	"github.com/xsscan/xsscan/pkg/scanner"
	"github.com/xsscan/xsscan/pkg/stored"
)

func configureTypes(cmd *cobra.Command) error {
	kinds, err := orchestrator.Select(cfg.Types, cfg.ExcludeTypes)
	if err != nil {
		return err
	}
	selected := make(map[orchestrator.Type]bool)
	for _, kind := range kinds {
		selected[kind] = true
	}
	for _, legacy := range []struct {
		flag    string
		kind    orchestrator.Type
		enabled bool
	}{{"headless", orchestrator.DOM, cfg.Headless}, {"stored", orchestrator.Stored, cfg.EnableStored}} {
		explicit := false
		if cmd != nil && cmd.Flags().Changed(legacy.flag) {
			explicit = true
		} else if enabled, ok := cfg.legacyTypeFlags[legacy.flag]; ok {
			explicit = true
			legacy.enabled = enabled
		}
		if !explicit {
			continue
		}
		if legacy.enabled {
			if (cfg.typesExplicit || (cmd != nil && cmd.Flags().Changed("types"))) && !selected[legacy.kind] {
				return fmt.Errorf("--%s contradicts types selection", legacy.flag)
			}
			selected[legacy.kind] = true
		} else {
			delete(selected, legacy.kind)
		}
	}

	var names []string
	for _, kind := range []orchestrator.Type{orchestrator.Reflected, orchestrator.DOM, orchestrator.Stored, orchestrator.Blind} {
		if selected[kind] {
			names = append(names, string(kind))
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("no scan types selected")
	}
	cfg.Types = strings.Join(names, ",")
	cfg.ExcludeTypes = ""
	cfg.Headless = selected[orchestrator.DOM]
	cfg.EnableStored = selected[orchestrator.Stored]
	if cfg.ModuleTimeout < 0 || cfg.RequestBudget < 0 {
		return fmt.Errorf("scan budgets must not be negative")
	}
	return nil
}

func selectedType(name string) bool {
	kinds, err := orchestrator.Select(cfg.Types, cfg.ExcludeTypes)
	if err != nil {
		return false
	}
	for _, kind := range kinds {
		if string(kind) == name {
			return true
		}
	}
	return false
}

// CLI composes dependencies; Runner owns type scheduling and lifecycle. The
// legacy reflected discovery helper is retained while modules migrate.
func runSelectedModules(ctx context.Context, engine *scanner.Engine, client *http.Client, urls []string, base model.Target, srv *callback.Server, findings *[]model.Finding, stats *model.ScanStats) error {
	kinds, err := orchestrator.Select(cfg.Types, cfg.ExcludeTypes)
	if err != nil {
		return err
	}
	modules := []orchestrator.Module{
		{Type: orchestrator.Reflected, Run: func(ctx context.Context, target model.Target) (*model.ScanResult, error) {
			return engine.Run(ctx, target)
		}},
		orchestrator.DOMModule(client, time.Duration(cfg.Timeout)*time.Second, cfg.VerifyExecution),
		orchestrator.StoredModule(client, stored.Config{TriggerURLs: cfg.TriggerURLs, PollingInterval: time.Duration(cfg.StoredPollInterval) * time.Second, MaxPolls: cfg.StoredMaxPolls, RequestTimeout: time.Duration(cfg.Timeout) * time.Second, Concurrency: cfg.Workers, VerifyExecution: cfg.VerifyExecution, VerifyTimeout: time.Duration(cfg.VerifyTimeout) * time.Second}, cfg.DiscoverHeaders),
		{Type: orchestrator.Blind, Check: func(context.Context, model.Target) error {
			if cfg.Callback == "" {
				return fmt.Errorf("callback endpoint not configured")
			}
			if isLocalCallback(cfg.Callback) && srv == nil {
				return fmt.Errorf("local callback listener unavailable")
			}
			return nil
		}, Run: func(ctx context.Context, target model.Target) (*model.ScanResult, error) {
			config := blind.Config{Callback: cfg.Callback, DiscoverHeaders: cfg.DiscoverHeaders}
			if srv != nil {
				config.Callback = srv.BaseURL()
				config.Observe = func(ctx context.Context) ([]callback.Callback, error) {
					callbacks := srv.ObserveWindow(ctx, 30*time.Second)
					return callbacks, ctx.Err()
				}
			}
			return blind.New(client, config).Scan(ctx, target)
		}},
	}
	if counter, ok := client.Transport.(interface{ Count() int64 }); ok {
		for i := range modules {
			run := modules[i].Run
			modules[i].Run = func(ctx context.Context, target model.Target) (*model.ScanResult, error) {
				before := counter.Count()
				result, err := run(ctx, target)
				if result != nil {
					result.Stats.RequestsSent = int(counter.Count() - before)
				}
				return result, err
			}
		}
	}
	runner, err := orchestrator.New(orchestrator.Plan{Types: kinds, ModuleTimeout: time.Duration(cfg.ModuleTimeout) * time.Second}, modules...)
	if err != nil {
		return err
	}
	var problems []error
	discoverer := orchestrator.Discoverer{Client: client, Config: orchestrator.DiscoveryConfig{Crawl: cfg.Crawl, RenderSPA: cfg.RenderSPA, Depth: cfg.CrawlDepth, MaxPages: cfg.CrawlMaxPages}}
	for _, rawURL := range urls {
		model.ReportProgress(ctx, "page discovery", 0, 0)
		targets, discoveryIssues := discoverer.Expand(ctx, deriveTarget(base, rawURL))
		if len(discoveryIssues) > 0 {
			stats.Status = model.MergeStatus(stats.Status, model.ScanFailed)
			stats.Issues = append(stats.Issues, discoveryIssues...)
			stats.Errors += len(discoveryIssues)
			for _, issue := range discoveryIssues {
				problems = append(problems, fmt.Errorf("%s: %s", issue.Stage, issue.Message))
			}
		}
		for _, target := range targets {
			result, err := runner.Run(ctx, target)
			if result != nil {
				*findings = append(*findings, result.Findings...)
				stats.Modules = append(stats.Modules, result.Stats.Modules...)
				stats.Coverage = append(stats.Coverage, result.Stats.Coverage...)
				for _, observation := range result.Stats.CrossModule.Observations {
					stats.CrossModule.Add(observation)
				}
				stats.Status = model.MergeStatus(stats.Status, result.Stats.Status)
				stats.Issues = append(stats.Issues, result.Stats.Issues...)
				stats.Errors += result.Stats.Errors
				stats.PayloadsSent += result.Stats.PayloadsSent
				stats.ParametersFound += result.Stats.ParametersFound
				stats.ProbeFiltered += result.Stats.ProbeFiltered
				if result.Stats.WAF != nil && (stats.WAF == nil || result.Stats.WAF.Bypassed) {
					stats.WAF = result.Stats.WAF
				}
			}
			if err != nil {
				problems = append(problems, err)
			}
		}
	}
	return errors.Join(problems...)
}

func isLocalCallback(raw string) bool {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	// This is capability classification, not address authorization.
	u, err := http.NewRequest(http.MethodGet, raw, nil)
	return err == nil && isLoopbackHost(u.URL.Hostname())
}
