package model

import (
	"fmt"
	"sort"
	"strings"
)

/*
Cross-module state summary (ENGINEERING_PLAN.md §25.9).

Each detection module reports on its own axis: reflected XSS says nothing about whether
a payload is stored, DOM XSS says nothing about server-side output encoding, and blind
XSS says nothing until a callback arrives. The summary therefore carries observations
that later work can use as *leads* — a WAF that answered, an origin that refused
authentication, a browser that was unavailable — and deliberately carries nothing else.

Two properties are enforced by construction rather than by convention:

  - There is no representation for "not exploitable". The observation kinds name what was
    seen or what could not be checked; there is no kind meaning "the target is safe on
    this axis", so a conclusion drawn in one module cannot be recorded here, let alone
    reused by another. A module that completed without findings is recorded as exactly
    that — an observation about the module — not as a statement about the target.
  - Every observation is derived from a recorded module outcome (its status, its counts,
    its issues), never from a suspicion. If a later reader wants to know why an
    observation is present, the same data is in ModuleResult.
*/

// ObservationKind names what a cross-module observation records.
type ObservationKind string

const (
	ObservationModuleSkipped ObservationKind = "module_skipped"
	// ObservationWAFAnswered records that requests were answered in a way a WAF explains.
	ObservationWAFAnswered ObservationKind = "waf_answered"
	// ObservationOriginUnreachable records that the origin did not answer usefully.
	ObservationOriginUnreachable ObservationKind = "origin_unreachable"
	// ObservationAuthRequired records that the target refused the request's credentials.
	ObservationAuthRequired ObservationKind = "auth_required"
	// ObservationBrowserUnavailable records that a browser-backed check could not run.
	ObservationBrowserUnavailable ObservationKind = "browser_unavailable"
	// ObservationCallbackUnavailable records that a delayed-callback check could not run.
	ObservationCallbackUnavailable ObservationKind = "callback_unavailable"
	// ObservationNoIndependentTrigger records that stored detection had no separate page
	// to observe the value on.
	ObservationNoIndependentTrigger ObservationKind = "no_independent_trigger"
	// ObservationFewParameters records that an injection point was found but few or none
	// were available.
	ObservationFewParameters ObservationKind = "few_parameters"
	// ObservationModuleIncomplete records that a module did not finish, so its silence
	// carries no information at all.
	ObservationModuleIncomplete ObservationKind = "module_incomplete"
	// ObservationNoFindings records that a module finished and reported nothing. This is
	// an observation about the module, never a conclusion about the target.
	ObservationNoFindings ObservationKind = "module_completed_without_findings"
)

// CrossModuleObservation is one lead produced by a module and made available to the run.
type CrossModuleObservation struct {
	Module  string          `json:"module"`
	Kind    ObservationKind `json:"kind"`
	Subject string          `json:"subject,omitempty"`
	Detail  string          `json:"detail"`
	// Probeable records whether the observation suggests something concrete to try. It
	// is a hint about usefulness, not a claim about exploitability.
	Probeable bool `json:"probeable"`
}

// CrossModuleSummary is the run-level list of leads. It is flat and bounded by the number
// of modules and their issues, so it cannot grow with payload count.
type CrossModuleSummary struct {
	Observations []CrossModuleObservation `json:"observations,omitempty"`
}

// Add appends an observation, keeping the summary free of duplicates on
// (module, kind, subject).
func (s *CrossModuleSummary) Add(observation CrossModuleObservation) {
	key := observation.Module + "\x00" + string(observation.Kind) + "\x00" + observation.Subject
	for _, existing := range s.Observations {
		if existing.Module+"\x00"+string(existing.Kind)+"\x00"+existing.Subject == key {
			return
		}
	}
	s.Observations = append(s.Observations, observation)
}

// Sorted returns the observations in a stable order for reporting.
func (s CrossModuleSummary) Sorted() []CrossModuleObservation {
	out := append([]CrossModuleObservation(nil), s.Observations...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// LeasForModule returns the observations a given module could act on.
//
// It exists so a module can consult leads without gaining access to another module's
// results: what crosses the boundary is the observation, not the verdict that produced it.
func (s CrossModuleSummary) LeadsForModule(module string) []CrossModuleObservation {
	var out []CrossModuleObservation
	for _, observation := range s.Sorted() {
		if observation.Module != module && observation.Probeable {
			out = append(out, observation)
		}
	}
	return out
}

// Describe renders the summary for reports.
func (s CrossModuleSummary) Describe() string {
	observations := s.Sorted()
	if len(observations) == 0 {
		return "no cross-module observations"
	}
	parts := make([]string, 0, len(observations))
	for _, observation := range observations {
		subject := ""
		if observation.Subject != "" {
			subject = " (" + observation.Subject + ")"
		}
		parts = append(parts, fmt.Sprintf("%s: %s%s — %s", observation.Module, observation.Kind, subject, observation.Detail))
	}
	return strings.Join(parts, "; ")
}

// BuildCrossModuleSummary derives the run's leads from what the modules actually
// recorded.
//
// Only recorded outcomes are read: each module's status, its counts, its issues and the
// run-level WAF result. Nothing is inferred from the absence of one of those, because
// absence of evidence is exactly what must not travel between modules.
func BuildCrossModuleSummary(modules []ModuleResult, waf *WAFInfo, parametersFound int) CrossModuleSummary {
	var summary CrossModuleSummary

	if waf != nil {
		detail := "a web application firewall was identified as " + waf.Name
		if waf.Bypassed {
			detail += " and a bypass was observed to work"
		}
		summary.Add(CrossModuleObservation{
			Module: "run", Kind: ObservationWAFAnswered, Subject: waf.Name,
			Detail: detail, Probeable: true,
		})
	}

	for _, module := range modules {
		switch module.Status {
		case ScanSkipped:
			// A skipped module states its own reason. Classify only what the reason
			// actually says, and keep the original text either way.
			kind, probeable := classifySkipReason(module.Reason)
			summary.Add(CrossModuleObservation{
				Module: module.Type, Kind: kind, Subject: module.Target,
				Detail: module.Reason, Probeable: probeable,
			})
		case ScanFailed, ScanCanceled, ScanPartial:
			summary.Add(CrossModuleObservation{
				Module: module.Type, Kind: ObservationModuleIncomplete, Subject: module.Target,
				Detail: incompleteDetail(module), Probeable: false,
			})
		}

		for _, issue := range module.Issues {
			if kind, ok := classifyIssue(issue); ok {
				summary.Add(CrossModuleObservation{
					Module: module.Type, Kind: kind, Subject: issue.Target,
					Detail: issue.Message, Probeable: kind == ObservationAuthRequired || kind == ObservationWAFAnswered,
				})
			}
		}

		if module.Status == ScanCompleted && module.Findings == 0 {
			summary.Add(CrossModuleObservation{
				Module: module.Type, Kind: ObservationNoFindings, Subject: module.Target,
				Detail: fmt.Sprintf("%s completed with no findings across %d candidate(s)", module.Type, module.Candidates),
			})
		}
		if module.Candidates == 0 && module.Status == ScanCompleted {
			summary.Add(CrossModuleObservation{
				Module: module.Type, Kind: ObservationFewParameters, Subject: module.Target,
				Detail: "no candidate was produced, so the module had nothing to test",
			})
		}
	}

	if parametersFound == 0 {
		summary.Add(CrossModuleObservation{
			Module: "run", Kind: ObservationFewParameters,
			Detail: "the run found no parameters to inject into on any module",
		})
	}
	return summary
}

func incompleteDetail(module ModuleResult) string {
	detail := string(module.Status)
	if module.Reason != "" {
		detail += ": " + module.Reason
	}
	return detail
}

// classifySkipReason maps a skip reason to an observation, matching only on wording the
// modules actually produce so an unrecognised reason stays unclassified instead of being
// forced into a category.
func classifySkipReason(reason string) (ObservationKind, bool) {
	lower := strings.ToLower(reason)
	switch {
	case strings.Contains(lower, "callback"):
		return ObservationCallbackUnavailable, false
	case strings.Contains(lower, "chrome"), strings.Contains(lower, "browser"):
		return ObservationBrowserUnavailable, false
	case strings.Contains(lower, "trigger"):
		return ObservationNoIndependentTrigger, true
	case strings.Contains(lower, "auth"), strings.Contains(lower, "credential"):
		return ObservationAuthRequired, true
	}
	return ObservationModuleSkipped, false
}

// classifyIssue maps a recorded issue to an observation when the issue's stage or message
// identifies one. Issues that identify nothing are left out rather than guessed at.
func classifyIssue(issue ScanIssue) (ObservationKind, bool) {
	stage := strings.ToLower(issue.Stage)
	message := strings.ToLower(issue.Message)
	switch {
	case strings.Contains(stage, "auth"), strings.Contains(message, "status 401"), strings.Contains(message, "authentication failed"):
		return ObservationAuthRequired, true
	case strings.Contains(stage, "browser"), strings.Contains(message, "chrome"):
		return ObservationBrowserUnavailable, true
	case strings.Contains(stage, "waf"):
		return ObservationWAFAnswered, true
	case strings.Contains(message, "connection refused"), strings.Contains(message, "no such host"),
		strings.Contains(message, "timeout"), strings.Contains(message, "deadline exceeded"):
		return ObservationOriginUnreachable, true
	}
	return "", false
}

// ObservationDetail explains a kind in one sentence.
func ObservationDetail(kind ObservationKind) string {
	switch kind {
	case ObservationModuleSkipped:
		return "the module was skipped for its recorded reason; the cause was not classified"
	case ObservationWAFAnswered:
		return "requests were answered in a way a web application firewall explains; later checks may need bypass handling"
	case ObservationOriginUnreachable:
		return "the origin did not answer usefully; nothing was learned about its behaviour"
	case ObservationAuthRequired:
		return "the target refused the request's credentials; the check did not reach the protected content"
	case ObservationBrowserUnavailable:
		return "a browser-backed check could not run; its silence is not evidence about the target"
	case ObservationCallbackUnavailable:
		return "a delayed-callback check could not run; no callback only means none arrived in the observation window"
	case ObservationNoIndependentTrigger:
		return "stored detection had no separate page to observe the injected value on"
	case ObservationFewParameters:
		return "little or nothing was available to inject into"
	case ObservationModuleIncomplete:
		return "the module did not finish, so its silence carries no information"
	case ObservationNoFindings:
		return "the module finished and reported nothing; this is an observation about the module, not a conclusion about the target"
	}
	return "unclassified observation"
}
