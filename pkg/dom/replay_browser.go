package dom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	allocopts "github.com/xsscan/xsscan/pkg/internal/chromedp"
	"github.com/xsscan/xsscan/pkg/model"
)

/*
Independent replay of a DOM candidate (ENGINEERING_PLAN.md §25.7).

A DOM observation is made with the scanner's marker inside the input, because the marker
is what the hooks match on. That observation therefore describes the *instrumented*
input, and the plan is explicit that it must not be transferred unconditionally to the
original value: "对支持的原始载荷与关联探针分别保留实际值及结果，不把instrumented候选的
成功无条件转移给原值".

This file performs that second, separate observation. It restores the input channel from
the candidate's descriptor, loads it in a fresh browser context, and looks for the
*unmarked* payload reaching the same sink. Two things make the result trustworthy rather
than merely convenient:

  - The replay runs in its own browser context with its own marker-free instrumentation.
    Sharing the observing context would let the original run's state stand in for the
    replay's, which is the transfer the plan forbids.
  - The input shape really does change: the observing run delivers "marker=payload"
    (or keys storage under the marker), while the replay delivers the bare payload. A
    page that reads its input positionally therefore sees different bytes, which is a
    genuine limitation of the observation and is reported as such instead of being
    smoothed over.
*/

// replayOutcome states what the replay established.
type replayOutcome string

const (
	// replayReachedPlain means the unmarked payload itself arrived at the same sink.
	// This is the only outcome that strengthens the candidate.
	replayReachedPlain replayOutcome = "plain_payload_reached_sink"
	// replayInputDiverged means the replay's input differed from the observing run's, so
	// the two runs are not comparable and nothing is concluded either way.
	replayInputDiverged replayOutcome = "input_shape_diverged"
	// replayNotReached means the replay delivered the input but the sink did not receive
	// the unmarked payload.
	replayNotReached replayOutcome = "plain_payload_not_observed"
	// replayError means the replay could not be performed, so the candidate keeps the
	// evidence it already had and gains nothing.
	replayError replayOutcome = "replay_not_performed"
)

// replayResult is the outcome of one independent replay attempt.
type replayResult struct {
	Err     error
	Outcome replayOutcome
	// Detail explains the outcome for a report reader.
	Detail string
	// Sinks lists the sink names the unmarked payload reached.
	Sinks []string
}

// confirmed reports whether the replay strengthens the candidate.
func (r replayResult) confirmed() bool { return r.Outcome == replayReachedPlain }

// replayDOMCandidate makes a second, independent observation of a DOM candidate using
// the original (unmarked) payload.
//
// The returned result never claims more than it observed: reaching the sink is not
// execution proof, and an inconclusive replay leaves the candidate exactly as it was.
func (s *Scanner) replayDOMCandidate(ctx context.Context, target model.Target, finding model.Finding, descriptor replayDescriptor, plainPayload string) (out replayResult) {
	if plainPayload == "" {
		return replayResult{Outcome: replayError, Detail: "candidate has no payload to replay"}
	}
	if descriptor.Unknown != "" {
		// The input channel is not known, so the replay would exercise some other input.
		return replayResult{
			Outcome: replayInputDiverged,
			Detail:  "input channel not established: " + descriptor.Unknown,
		}
	}
	if target.HTTPMethod() != http.MethodGet || target.Body != "" {
		return replayResult{Outcome: replayError, Detail: "DOM navigation cannot reproduce the original request method/body"}
	}

	// A fresh browser context, so the observing run's storage, cookies and hooks cannot
	// stand in for this one.
	replayCtx, cancelReplay, diagnostics, err := allocopts.NewIsolatedTabContext(ctx, s.browserCtx, s.timeout)
	if err != nil {
		return replayResult{Outcome: replayError, Detail: "create isolated replay context: " + err.Error()}
	}
	defer func() {
		cancelReplay()
		if err := diagnostics.Err(); err != nil {
			out = replayResult{Outcome: replayError, Detail: err.Error(), Err: errors.Join(out.Err, err)}
		}
		if err := diagnostics.CleanupErr(); err != nil {
			out.Detail += "; " + err.Error()
			out.Err = errors.Join(out.Err, err)
		}
	}()
	replayCtx, cancelTimeout := context.WithTimeout(replayCtx, 20*time.Second)
	defer cancelTimeout()
	stopDialogs := allocopts.ListenDialogs(replayCtx, cancelTimeout, false, nil)
	defer stopDialogs()
	guard, policy := allocopts.GuardRequests(target.URL, cancelTimeout, nil)
	defer func() {
		guard.Close()
		if err := guard.Err(); err != nil {
			out.Outcome = replayError
			out.Detail = err.Error()
			out.Err = err
		}
	}()
	if err := chromedp.Run(replayCtx, policy); err != nil {
		return replayResult{Outcome: replayError, Detail: "replay request policy: " + err.Error()}
	}
	if err := s.applyTargetState(replayCtx, target); err != nil {
		return replayResult{Outcome: replayError, Detail: "replay authentication: " + err.Error()}
	}

	// Marker-free instrumentation: the hooks still record what reaches each sink, but
	// they no longer filter on a marker, so the unmarked payload is observable.
	hookScript := buildReplayHookScript()
	injectReplayHook := chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(hookScript).Do(ctx)
		return err
	})
	if err := chromedp.Run(replayCtx, injectReplayHook); err != nil {
		return replayResult{Outcome: replayError, Detail: "install replay instrumentation: " + err.Error()}
	}

	if err := s.seedReplayState(replayCtx, target, descriptor, plainPayload); err != nil {
		return replayResult{Outcome: replayError, Detail: "seed initial state: " + err.Error()}
	}

	navURL := buildReplayURL(target.URL, descriptor, plainPayload)
	activity := &pageActivity{}
	chromedp.ListenTarget(replayCtx, activity.observe)

	if err := chromedp.Run(replayCtx, chromedp.Navigate(navURL)); err != nil {
		return replayResult{Outcome: replayError, Detail: "navigate for replay: " + err.Error()}
	}
	// A page that never settles still has observable sink state, so a settle warning is
	// recorded in the outcome rather than aborting the replay.
	var settleNotes []string
	if err := activity.wait(replayCtx, 2*time.Second); err != nil {
		settleNotes = append(settleNotes, "settle: "+err.Error())
	}
	if descriptor.Interaction != "" {
		if err := s.performReplayInteraction(replayCtx, descriptor, plainPayload); err != nil {
			return replayResult{Outcome: replayError, Detail: "replay interaction: " + err.Error()}
		}
		if err := activity.wait(replayCtx, time.Second); err != nil {
			settleNotes = append(settleNotes, "interaction settle: "+err.Error())
		}
	}

	var recorded []replaySinkRecord
	if err := chromedp.Run(replayCtx, chromedp.Evaluate(`window.__xsscan_replay_sinks || []`, &recorded)); err != nil {
		return replayResult{Outcome: replayError, Detail: "read replay sink records: " + err.Error()}
	}
	if err := guard.Err(); err != nil {
		return replayResult{Outcome: replayError, Detail: err.Error()}
	}

	note := ""
	if len(settleNotes) > 0 {
		note = " (page did not fully settle: " + strings.Join(settleNotes, "; ") + ")"
	}
	var reached []string
	for _, rec := range recorded {
		if strings.Contains(rec.Value, plainPayload) {
			reached = append(reached, rec.Sink)
		}
	}
	if len(reached) > 0 {
		return replayResult{
			Outcome: replayReachedPlain,
			Sinks:   reached,
			Detail: "the unmarked payload itself reached " + strings.Join(reached, ", ") +
				"; this is a second observation of the input, not execution proof" + note,
		}
	}
	return replayResult{
		Outcome: replayNotReached,
		Detail: fmt.Sprintf("the unmarked payload was delivered but not observed at any sink (%d sink calls recorded); "+
			"the observing run's conclusion is not transferred to it", len(recorded)) + note,
	}
}

// seedReplayState restores the pre-existing state the descriptor records.
//
// Storage and cookies need the target origin, which about:blank does not provide, so the
// target page is loaded once and the state written there before the replay navigation.
func (s *Scanner) seedReplayState(ctx context.Context, target model.Target, descriptor replayDescriptor, value string) error {
	if descriptor.Seed == "" {
		return nil
	}
	switch descriptor.Source {
	case replaySourceLocalStore, replaySourceSessStore, replaySourceWindowName:
		// Written on the target origin, then the replay navigation re-reads it.
		key := descriptor.InputName
		if key == "" {
			key = "xsscan-replay"
		}
		store := "localStorage"
		if descriptor.Source == replaySourceSessStore {
			store = "sessionStorage"
		}
		setup := fmt.Sprintf("%s.setItem(%s,%s);", store, jsStringLiteral(key), jsStringLiteral(value))
		if descriptor.Source == replaySourceWindowName {
			setup = fmt.Sprintf("window.name=%s;", jsStringLiteral(value))
		}
		if err := chromedp.Run(ctx, chromedp.Navigate(target.URL)); err != nil {
			return err
		}
		return chromedp.Run(ctx, chromedp.Evaluate(setup, nil))
	case replaySourceCookie:
		name := descriptor.InputName
		if name == "" {
			name = "xsscan-replay"
		}
		return chromedp.Run(ctx, network.SetCookies([]*network.CookieParam{{
			Name: name, Value: value, URL: target.URL, Path: "/",
		}}))
	case replaySourceReferrer:
		// Referrer is spoofed per-document, so it is installed as a new-document script.
		script := fmt.Sprintf("Object.defineProperty(document,'referrer',{get:()=>%s});", jsStringLiteral(value))
		injectReferrer := chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(script).Do(ctx)
			return err
		})
		return chromedp.Run(ctx, injectReferrer)
	default:
		// Sources consumed directly from the URL need no seeding.
		return nil
	}
}

// buildReplayURL places the plain payload on the channel the descriptor names.
func buildReplayURL(targetURL string, descriptor replayDescriptor, value string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	switch descriptor.Source {
	case replaySourceFragment:
		return buildURLWithFragment(u, value)
	case replaySourceQuery:
		key := descriptor.InputName
		if key == "" {
			key = "xsscan"
		}
		return buildURLWithQuery(u, key, value)
	case replaySourcePath:
		return buildURLWithPathPrefix(u, value)
	default:
		return targetURL
	}
}

// performReplayInteraction reproduces the post-load action the descriptor records.
func (s *Scanner) performReplayInteraction(ctx context.Context, descriptor replayDescriptor, value string) error {
	switch descriptor.Source {
	case replaySourcePostMessage:
		return chromedp.Run(ctx, chromedp.Evaluate(
			fmt.Sprintf("window.postMessage(%s,'*');", jsStringLiteral(value)), nil))
	case replaySourceJSHref:
		// The crafted link has to be navigated to; the page itself does not follow it.
		return chromedp.Run(ctx, chromedp.Evaluate(
			`(function(){var a=document.querySelector('a[href^="javascript:"]');if(a){a.click();}})()`, nil))
	default:
		return nil
	}
}

// replaySinkRecord is one sink call observed by the replay instrumentation.
type replaySinkRecord struct {
	Sink  string `json:"sink"`
	Value string `json:"value"`
}

// buildReplayHookScript produces instrumentation that records every sink call instead of
// only those carrying a marker.
//
// The marker filter is what makes the observing run's records meaningful, and it is also
// exactly what makes them useless for the unmarked payload: with the filter in place the
// replay could never observe what it is looking for.
func buildReplayHookScript() string {
	return `(function(){
    'use strict';
    var sinks = [];
    function record(name, v) {
        if (sinks.length >= 200) { return; }
        if (typeof v !== 'string' || v.length === 0) { return; }
        sinks.push({sink: name, value: v.substring(0, 2000)});
    }
    try {
        var d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (d && d.set) { Object.defineProperty(Element.prototype, 'innerHTML', {get: d.get,
            set: function(v){ record('innerHTML', String(v)); d.set.call(this, v); }, configurable: true, enumerable: true}); }
    } catch(e){}
    try {
        var ow = Document.prototype.write;
        Document.prototype.write = function(){ for (var i=0;i<arguments.length;i++){ record('document.write', String(arguments[i])); } return ow.apply(this, arguments); };
    } catch(e){}
    try {
        var ev = window.eval;
        window.eval = function(c){ record('eval', String(c)); return ev(c); };
    } catch(e){}
    try {
        var sa = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(n, v){ if (typeof n === 'string' && /^on\w+$/i.test(n)) { record('setAttribute('+n.toLowerCase()+')', String(v)); } return sa.call(this, n, v); };
    } catch(e){}
    try {
        var ih = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function(p, h){ record('insertAdjacentHTML', String(h)); return ih.call(this, p, h); };
    } catch(e){}
    window.__xsscan_replay_sinks = sinks;
})();`
}
