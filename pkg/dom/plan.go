package dom

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/chromedp/chromedp"
	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/jsanalysis"
	"github.com/xsscan/xsscan/pkg/model"
)

type documentPlan struct {
	flows []model.JSDataFlow
	err   error
}

// Include cookies explicitly: Target's JSON deliberately omits them. Plans must
// never be reused across different authenticated requests, even on one URL.
func (s *Scanner) requestPlanKey(target model.Target) ([sha256.Size]byte, error) {
	data, err := json.Marshal(struct {
		Target    model.Target
		Cookies   []*http.Cookie
		Auth      *AuthState
		ProxyAuth string
	}{target, target.Cookies, s.auth, target.ProxyAuth})
	return sha256.Sum256(data), err
}
func (s *Scanner) checkTargetPlan(ctx context.Context, target model.Target) (*documentPlan, error) {
	plan := &documentPlan{}
	model.ReportProgress(ctx, "DOM JS data-flow planning", 0, 0)
	_, err := s.runSingleDOMTest(ctx, target, domXSSTest{Name: "baseline", NavURL: target.URL}, analyze.GenerateMarker(), "", plan)
	if err != nil {
		return nil, err
	}
	if key, err := s.requestPlanKey(target); err == nil {
		s.planMu.Lock()
		s.planKey, s.plan = key, plan
		s.planMu.Unlock()
	}
	return plan, nil
}
func (s *Scanner) targetPlan(ctx context.Context, target model.Target) (*documentPlan, error) {
	if key, err := s.requestPlanKey(target); err == nil {
		s.planMu.RLock()
		plan, match := s.plan, s.planKey == key
		s.planMu.RUnlock()
		if plan != nil && match {
			return plan, nil
		}
	}
	return s.checkTargetPlan(ctx, target)
}

func collectDocumentPlan(ctx context.Context, plan *documentPlan) error {
	var scripts []struct {
		Text   string `json:"text"`
		Module bool   `json:"module"`
		Index  int    `json:"index"`
	}
	// Reuse the already-loaded page. No external scripts, dependency fetches or
	// unbounded transfer of a minified bundle are introduced by planning.
	err := chromedp.Run(ctx, chromedp.Evaluate(`(()=>{const out=[];let total=0;const all=document.scripts;for(let i=0;i<Math.min(all.length,64);i++){const s=all[i];const type=(s.getAttribute('type')||'').trim().toLowerCase();if(s.src||!['','module','text/javascript','application/javascript','text/ecmascript','application/ecmascript'].includes(type))continue;const text=s.textContent||'';if(text.length>262144||total+text.length>1048576)continue;total+=text.length;out.push({text,module:type==='module',index:i+1});}return out;})()`, &scripts))
	if err != nil {
		return fmt.Errorf("read inline JavaScript for DOM planning: %w", err)
	}
	for _, script := range scripts {
		mode := jsanalysis.ScriptMode
		if script.Module {
			mode = jsanalysis.ModuleMode
		}
		a := jsanalysis.ParseWithMode(script.Text, mode)
		// Unknown or limited static analysis never drops the original matrix.
		for _, flow := range a.Flows {
			if len(plan.flows) == 128 {
				return nil
			}
			plan.flows = append(plan.flows, model.JSDataFlow{Source: flow.Source.Kind, Key: flow.Source.Key, Sink: flow.Sink, ScriptIndex: script.Index, SourceStart: flow.Source.Start, SourceEnd: flow.Source.End, SinkStart: flow.Start, SinkEnd: flow.End})
		}
	}
	return nil
}

func buildPlannedDOMTests(u *url.URL, payload, marker string, plan *documentPlan) []domXSSTest {
	tests := buildDOMTests(u, payload, marker)
	if plan == nil {
		return tests
	}
	indices := make(map[string]int, len(tests))
	for i, t := range tests {
		indices[t.Name] = i
	}
	added := 0
	for _, flow := range plan.flows {
		name := flow.Source
		if flow.Source == "query" {
			name = "search"
		}
		if flow.Key != "" {
			name += ":" + flow.Key
		}
		index, ok := indices[name]
		if !ok {
			if flow.Key == "" || added == 24 {
				continue
			}
			probe := domXSSTest{Name: name, Source: "JavaScript data-flow input " + flow.Source + "[" + flow.Key + "]", NavURL: u.String()}
			value := marker + "=" + payload
			switch flow.Source {
			case "query":
				probe.NavURL = buildURLWithQuery(u, flow.Key, value)
			case "fragment":
				probe.NavURL = buildURLWithFragment(u, url.Values{flow.Key: []string{value}}.Encode())
			case "localStorage", "sessionStorage":
				probe.Extra = fmt.Sprintf("%s.setItem(%s,%s);", flow.Source, jsStringLiteral(flow.Key), jsStringLiteral(value))
			default:
				continue
			}
			index = len(tests)
			indices[name] = index
			tests = append(tests, probe)
			added++
		}
		// Keep hypotheses separate from the runtime marker hit. Only matching
		// sink names will be attached to a reported dynamic candidate.
		tests[index].Flows = append(tests[index].Flows, flow)
	}
	return tests
}

func plannedSourcePriority(test domXSSTest) int {
	if len(test.Flows) > 0 {
		return 3
	}
	if test.Name == "postMessage" {
		return 2
	}
	if strings.HasPrefix(test.Name, "search:") {
		return 1
	}
	return 0
}
