package orchestrator

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/wqnmlgb151/XSSscan/pkg/crawler"
	"github.com/wqnmlgb151/XSSscan/pkg/internal/request"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

type DiscoveryConfig struct {
	ExcludeURLs, IncludeURLs                []string
	Crawl, RenderSPA                        bool
	NoForms, AllowFormSubmit, Authenticated bool
	Depth, MaxPages                         int
}

// Discoverer expands one explicit target once for all detector types. Link
// following requires Crawl; same-page forms retain their actual HTTP method.
type Discoverer struct {
	Client *http.Client
	Config DiscoveryConfig
}

func (d Discoverer) Expand(ctx context.Context, base model.Target) ([]model.Target, []model.ScanIssue) {
	scope, err := crawler.NewURLScope(d.Config.ExcludeURLs, d.Config.IncludeURLs)
	if err != nil {
		return nil, []model.ScanIssue{{Target: base.URL, Stage: "scope", Message: err.Error()}}
	}
	if err = scope.Check(base.URL); err != nil {
		return nil, []model.ScanIssue{{Target: base.URL, Stage: "discovery-skip", Message: err.Error()}}
	}
	ctx = scope.Context(ctx)
	targets := []model.Target{base}
	var forms []crawler.FormInfo
	var issues []model.ScanIssue
	addIssue := func(stage string, err error) {
		if err != nil {
			issues = append(issues, model.ScanIssue{Target: base.URL, Stage: stage, Message: err.Error()})
		}
	}
	queryless := false
	if u, err := url.Parse(base.URL); err == nil {
		queryless = len(u.Query()) == 0
	}
	if d.Config.Crawl {
		c := crawler.NewCrawlerWithConfig(d.Client, crawler.CrawlerConfig{NoForms: d.Config.NoForms, Scope: scope, MaxDepth: d.Config.Depth, MaxPages: d.Config.MaxPages, SameHostOnly: true, ExtraHeaders: base.Headers})
		result, err := c.Crawl(ctx, base.URL)
		addIssue("crawl", err)
		if result != nil {
			forms = result.Forms
			issues = append(issues, result.Skipped...)
			for _, rawURL := range result.URLs {
				target := cloneTarget(base)
				target.URL = rawURL
				targets = append(targets, target)
			}
		}
	}
	if !d.Config.NoForms && base.Body == "" && (d.Config.Crawl || queryless) {
		info, err := crawler.ExtractPageInfo(ctx, d.Client, base.URL, base.Headers)
		addIssue("discovery", err)
		if info != nil {
			if queryless {
				forms = append(forms, info.Forms...)
			}
			if d.Config.Crawl {
				for _, mined := range info.ParamTargets {
					if err := scope.Check(mined.URL); err != nil {
						issues = append(issues, model.ScanIssue{Target: mined.URL, Stage: "discovery-skip", Message: err.Error()})
						continue
					}
					target := cloneTarget(base)
					u, err := url.Parse(mined.URL)
					if err != nil {
						continue
					}
					q := u.Query()
					for _, name := range mined.Params {
						if !q.Has(name) {
							q.Set(name, "test")
						}
					}
					u.RawQuery = q.Encode()
					target.URL = u.String()
					targets = append(targets, target)
				}
			}
		}
	}
	if !d.Config.NoForms && len(forms) == 0 && d.Config.RenderSPA && base.Body == "" && (queryless || d.Config.Crawl) {
		rendered, err := crawler.RenderPage(ctx, base.URL, base.Headers, 0)
		addIssue("render", err)
		if rendered != nil {
			forms = rendered.Forms
		}
	}
	for _, form := range forms {
		if err := scope.Check(form.Action); err != nil {
			issues = append(issues, model.ScanIssue{Target: form.Action, Stage: "discovery-skip", Message: err.Error()})
			continue
		}
		if d.Config.NoForms {
			continue
		}
		password := false
		for _, field := range form.Fields {
			if field.Type == "password" {
				password = true
			}
		}
		if password {
			issues = append(issues, model.ScanIssue{Target: form.Action, Stage: "discovery-skip", Message: "password form skipped"})
			continue
		}
		authenticated := d.Config.Authenticated || len(base.Cookies) > 0
		for name := range base.Headers {
			if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Cookie") {
				authenticated = true
			}
		}
		if authenticated && strings.EqualFold(form.Method, http.MethodPost) && !d.Config.AllowFormSubmit {
			issues = append(issues, model.ScanIssue{Target: form.Action, Stage: "discovery-skip", Message: "authenticated automatic POST form skipped; use --allow-form-submit to opt in"})
			continue
		}
		target := cloneTarget(base)
		target.URL, target.Method = form.Action, strings.ToUpper(form.Method)
		target.Body = ""
		for key := range target.Headers {
			if strings.EqualFold(key, "Content-Type") || strings.EqualFold(key, "Content-Length") {
				delete(target.Headers, key)
			}
		}
		if target.Method == "" {
			target.Method = http.MethodGet
		}
		values := form.DefaultValues()
		if target.Method == http.MethodPost {
			target.Body = values.Encode()
			if target.Headers == nil {
				target.Headers = make(map[string]string)
			}
			target.Headers[request.ContentTypeKey] = "application/x-www-form-urlencoded"
		} else {
			u, err := url.Parse(target.URL)
			if err != nil {
				continue
			}
			q := u.Query()
			for name, value := range values {
				q[name] = value
			}
			u.RawQuery = q.Encode()
			target.URL = u.String()
		}
		targets = append(targets, target)
	}
	seen := make(map[string]bool)
	unique := targets[:0]
	for _, target := range targets {
		key := target.HTTPMethod() + "\x00" + target.URL + "\x00" + target.Body
		if !seen[key] {
			seen[key] = true
			unique = append(unique, target)
		}
	}
	return unique, issues
}

func cloneTarget(target model.Target) model.Target {
	target.Headers = request.CloneHeaders(target.Headers)
	target.Cookies = request.CloneCookies(target.Cookies)
	return target
}
