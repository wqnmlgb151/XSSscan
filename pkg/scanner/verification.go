package scanner

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/execverify"
	"github.com/wqnmlgb151/XSSscan/pkg/internal/urlutil"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

type verificationKey struct {
	url, parameter, context, kind string
	paramType                     model.ParamType
}

// groupVerificationCandidates groups findings for execution verification.
//
// ReflectionPath separates request identities and candidate planning buckets.
// Same-type reflections can share the first anchor, so a bucket does not prove
// which position executed. A successful group retains the checked payload's
// evidence; alternatives are reproduction options, not independently verified.
// Missing paths use the legacy URL/parameter/context key. Neither grouping mode
// establishes per-position coverage.
func groupVerificationCandidates(findings []model.Finding) [][]model.Finding {
	positions := make(map[verificationKey]int)
	var groups [][]model.Finding
	for _, f := range findings {
		var key verificationKey
		if f.ReflectionPath != "" {
			// The path already contains the request's parameter identity.
			key = verificationKey{kind: string(f.Type), url: f.ReflectionPath, parameter: f.Parameter}
		} else {
			key = verificationKey{urlutil.NormalizeForDedup(f.URL), f.Parameter, string(primaryContextClass(parseContextTypes(f.Contexts))), string(f.Type), f.ParamType}
		}
		index, exists := positions[key]
		if !exists {
			index = len(groups)
			positions[key] = index
			groups = append(groups, nil)
		}
		groups[index] = append(groups[index], f)
	}
	for _, group := range groups {
		sort.SliceStable(group, func(i, j int) bool {
			a, b := execverify.SupportsDialogVerification(group[i].Payload), execverify.SupportsDialogVerification(group[j].Payload)
			if a != b {
				return a
			}
			if len(group[i].Payload) != len(group[j].Payload) {
				return len(group[i].Payload) < len(group[j].Payload)
			}
			return betterFinding(&group[j], &group[i])
		})
	}
	return groups
}

// Verify variants until one candidate proves this parameter/context group.
// Untried variants remain reproduction alternatives, never execution proofs.
func (e *Engine) verifyCandidateGroup(ctx context.Context, group []model.Finding, target model.Target, verifyFinding func(context.Context, model.Finding, model.Target) (*execverify.ExecutionResult, error)) []model.Finding {
	if len(group) == 0 {
		return nil
	}
	var checked []model.Finding
	var unsupported []model.Finding
	for i, f := range group {
		if err := ctx.Err(); err != nil {
			e.recordRunError("execution", err)
			checked = append(checked, e.unverifiedFindings(group[i:], err)...)
			break
		}
		if !execverify.SupportsDialogVerification(f.Payload) {
			unsupported = append(unsupported, f)
			continue
		}
		result, err := callExecutionVerifier(ctx, f, target, verifyFinding)
		if result == nil && err == nil {
			err = fmt.Errorf("execution verifier returned no result")
		}
		if err != nil {
			e.applyVerificationError(&f, result, err)
			// Keep failures visible even if a later variant proves execution.
			e.recordRunError("execution", err)
		} else {
			e.applyVerificationResult(&f, result)
		}
		checked = append(checked, f)
		if f.ExecutionVerified {
			for _, variant := range group {
				f.Payloads = append(f.Payloads, variant.Payload)
			}
			return []model.Finding{f}
		}
	}
	if len(unsupported) > 0 {
		unsupportedErr := fmt.Errorf("candidate in parameter %q has no supported dialog call for execution verification", group[0].Parameter)
		e.recordRunError("execution", unsupportedErr)
		for _, f := range unsupported {
			e.applyVerificationError(&f, nil, unsupportedErr)
			checked = append(checked, f)
		}
	}
	return checked
}

// A failed verifier must not unwind the worker goroutine or discard prior results.
func callExecutionVerifier(ctx context.Context, f model.Finding, target model.Target, verifyFinding func(context.Context, model.Finding, model.Target) (*execverify.ExecutionResult, error)) (result *execverify.ExecutionResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("execution verifier panic: %v", recovered)
		}
	}()
	return verifyFinding(ctx, f, target)
}

func (e *Engine) unverifiedFindings(findings []model.Finding, err error) []model.Finding {
	out := append([]model.Finding(nil), findings...)
	for i := range out {
		e.applyVerificationError(&out[i], nil, err)
	}
	return out
}

func (e *Engine) verifyGroupedFindings(ctx context.Context, findings []model.Finding, auth *execverify.AuthState, target model.Target) []model.Finding {
	groups := groupVerificationCandidates(findings)
	if len(groups) == 0 {
		return findings
	}
	if err := ctx.Err(); err != nil {
		e.recordRunError("execution", err)
		e.recordCoverage(model.CheckCoverage{Stage: "final_verification_groups", PlannedKnown: true, Planned: len(groups), NotStarted: len(groups)})
		return e.unverifiedFindings(findings, err)
	}
	timeout := e.config.VerifyTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	v, err := execverify.NewVerifierWithAuth(ctx, timeout, auth)
	if err != nil {
		e.recordRunError("execution", err)
		e.recordCoverage(model.CheckCoverage{Stage: "final_verification_groups", PlannedKnown: true, Planned: len(groups), NotStarted: len(groups)})
		return e.unverifiedFindings(findings, err)
	}
	defer func() { e.recordRunError("execution cleanup", v.Close()) }()
	return e.verifyGroups(ctx, groups, target, v.VerifyFinding)
}

// The unbuffered handoff limits active groups to four. Joining every worker here
// keeps the caller's deferred browser Close after all verification calls return.
func (e *Engine) verifyGroups(ctx context.Context, groups [][]model.Finding, target model.Target, verifyFinding func(context.Context, model.Finding, model.Target) (*execverify.ExecutionResult, error)) []model.Finding {
	coverage := model.CheckCoverage{Stage: "final_verification_groups", PlannedKnown: true, Planned: len(groups)}
	results := make([][]model.Finding, len(groups))
	outcomes := make([]string, len(groups))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var completed atomic.Int64
	model.ReportProgress(ctx, "execution verification groups", 0, len(groups))
	for range min(4, len(groups)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					results[i] = e.unverifiedFindings(groups[i], ctx.Err())
					continue
				}
				outcomes[i] = "completed"
				results[i] = e.verifyCandidateGroup(ctx, groups[i], target, verifyFinding)
				for _, finding := range results[i] {
					if finding.Evidence.VerificationError != "" {
						outcomes[i] = "failed"
						if ctx.Err() != nil {
							outcomes[i] = "canceled"
						}
						break
					}
				}
				model.ReportProgress(ctx, "execution verification groups", int(completed.Add(1)), len(groups))
			}
		}()
	}
	next := 0
dispatch:
	for next < len(groups) {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- next:
			next++
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	if next < len(groups) {
		err := ctx.Err()
		e.recordRunError("execution", err)
		for i := next; i < len(groups); i++ {
			results[i] = e.unverifiedFindings(groups[i], err)
		}
	}
	var out []model.Finding
	for i, group := range results {
		switch outcomes[i] {
		case "completed":
			coverage.Completed++
		case "failed":
			coverage.Failed++
		case "canceled":
			coverage.Canceled++
		default:
			coverage.NotStarted++
		}
		out = append(out, group...)
	}
	coverage.Started = coverage.Completed + coverage.Failed + coverage.Canceled
	e.recordCoverage(coverage)
	return out
}
