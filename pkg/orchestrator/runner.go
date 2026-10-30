package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
)

// Module adapts a detector to one run's common input, lifecycle and output.
type Module struct {
	Type  Type
	Check func(context.Context, model.Target) error
	Run   func(context.Context, model.Target) (*model.ScanResult, error)
}

type Runner struct {
	plan    Plan
	modules map[Type]Module
}

func New(plan Plan, modules ...Module) (*Runner, error) {
	if len(plan.Types) == 0 {
		plan.Types = append([]Type(nil), types...)
	}
	if plan.ModuleTimeout < 0 {
		return nil, fmt.Errorf("module timeout must not be negative")
	}
	plan.Types = append([]Type(nil), plan.Types...)
	seen := make(map[Type]bool)
	for _, kind := range plan.Types {
		if !validType(kind) || seen[kind] {
			return nil, fmt.Errorf("invalid or duplicate scan type %q", kind)
		}
		seen[kind] = true
	}
	r := &Runner{plan: plan, modules: make(map[Type]Module)}
	for _, module := range modules {
		if !validType(module.Type) || module.Run == nil {
			return nil, fmt.Errorf("invalid detector %q", module.Type)
		}
		if _, exists := r.modules[module.Type]; exists {
			return nil, fmt.Errorf("duplicate detector %q", module.Type)
		}
		r.modules[module.Type] = module
	}
	return r, nil
}

// Run retains one result for every selected module, including unavailable and
// canceled modules. Success never overwrites an incomplete module.
func (r *Runner) Run(ctx context.Context, target model.Target) (*model.ScanResult, error) {
	result := &model.ScanResult{Target: target.URL}
	var problems []error
	for _, kind := range r.plan.Types {
		model.ReportProgress(ctx, string(kind)+" checks", 0, 0)
		start := time.Now()
		module, exists := r.modules[kind]
		status := model.ScanCompleted
		var output *model.ScanResult
		var err error
		if ctx.Err() != nil {
			status, err = model.ScanCanceled, ctx.Err()
		} else if !exists {
			status, err = model.ScanSkipped, fmt.Errorf("detector not registered")
		} else {
			moduleCtx, cancel := context.WithCancel(ctx)
			if r.plan.ModuleTimeout > 0 {
				cancel()
				moduleCtx, cancel = context.WithTimeout(ctx, r.plan.ModuleTimeout)
			}
			if module.Check != nil {
				err = invokeCheck(moduleCtx, module, cloneTarget(target))
			}
			if err != nil {
				status = model.ScanSkipped
			} else {
				output, err = invoke(moduleCtx, module, cloneTarget(target))
				if output == nil && err == nil {
					err = fmt.Errorf("detector returned no result")
				}
				if err != nil {
					status = model.ScanFailed
					if hasWork(output) {
						status = model.ScanPartial
					}
				} else if output.Stats.Status != "" {
					status = output.Stats.Status
				}
				if output != nil {
					status = model.ResolveStatus(status, output.Stats.Modules, output.Stats.Issues, output.Stats.Errors)
				}
			}
			if moduleCtx.Err() != nil {
				err = errors.Join(err, moduleCtx.Err())
				status = model.ScanFailed
				if hasWork(output) {
					status = model.ScanPartial
				}
			}
			cancel()
			if ctx.Err() != nil {
				status = model.ScanCanceled
			}

		}
		mr := model.ModuleResult{Type: string(kind), Target: target.URL, Status: status, Duration: time.Since(start).Milliseconds()}
		if output != nil {
			result.Findings = append(result.Findings, output.Findings...)
			mr.Requests = output.Stats.RequestsSent
			mr.Candidates = output.Stats.PayloadsSent
			mr.Findings = len(output.Findings)
			mr.Issues = append(mr.Issues, output.Stats.Issues...)
			mr.Coverage = append([]model.CheckCoverage(nil), output.Stats.Coverage...)
			result.Stats.Coverage = append(result.Stats.Coverage, output.Stats.Coverage...)
			result.Stats.RequestsSent += output.Stats.RequestsSent
			result.Stats.PayloadsSent += output.Stats.PayloadsSent
			result.Stats.ParametersFound += output.Stats.ParametersFound
			result.Stats.ProbeFiltered += output.Stats.ProbeFiltered
			if output.Stats.WAF != nil && (result.Stats.WAF == nil || output.Stats.WAF.Bypassed) {
				result.Stats.WAF = output.Stats.WAF
			}
		}
		if err != nil {
			mr.Reason = err.Error()
			present := false
			for _, issue := range mr.Issues {
				present = present || issue.Message == err.Error()
			}
			if !present {
				mr.Issues = append(mr.Issues, model.ScanIssue{Target: target.URL, Stage: string(kind), Message: err.Error()})
			}
			problems = append(problems, fmt.Errorf("%s: %w", kind, err))
		} else if status != model.ScanCompleted {
			mr.Reason = "detector did not complete"
			if len(mr.Issues) > 0 {
				mr.Reason = mr.Issues[0].Message
			} else {
				mr.Issues = append(mr.Issues, model.ScanIssue{Target: target.URL, Stage: string(kind), Message: mr.Reason})
			}
			problems = append(problems, fmt.Errorf("%s: %s", kind, status))
		}
		result.Stats.Issues = append(result.Stats.Issues, mr.Issues...)
		moduleErrors := len(mr.Issues)
		if output != nil {
			// Diagnostics may collapse repeated failures into one message;
			// keep the detector's actual failure count in the run statistics.
			if output.Stats.Errors > 0 || len(output.Stats.Issues) > 0 {
				moduleErrors = max(len(output.Stats.Issues), output.Stats.Errors)
				if err != nil && len(output.Stats.Issues) > 0 {
					moduleErrors += unrecordedErrors(err, output.Stats.Issues)
				}
			}
		}
		result.Stats.Errors += moduleErrors
		result.Stats.Modules = append(result.Stats.Modules, mr)
		result.Stats.Status = model.MergeStatus(result.Stats.Status, status)
	}
	// Summarise the modules' recorded outcomes as leads for later work. This reads only
	// what the modules actually recorded, and deliberately has no way to express "not
	// exploitable" — a conclusion reached on one axis must not be reusable on another.
	result.Stats.CrossModule = model.BuildCrossModuleSummary(result.Stats.Modules, result.Stats.WAF, result.Stats.ParametersFound)
	return result, errors.Join(problems...)
}

// Count distinct error leaves, rather than treating a joined error as one
// already-recorded failure just because one of its children is known.
func unrecordedErrors(err error, issues []model.ScanIssue) int {
	seen := make(map[string]bool)
	var visit func(error) int
	visit = func(err error) int {
		if err == nil {
			return 0
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			count := 0
			for _, child := range joined.Unwrap() {
				count += visit(child)
			}
			return count
		}
		if wrapped, ok := err.(interface{ Unwrap() error }); ok {
			return visit(wrapped.Unwrap())
		}
		message := err.Error()
		if seen[message] {
			return 0
		}
		seen[message] = true
		for _, issue := range issues {
			if message != "" && strings.Contains(issue.Message, message) {
				return 0
			}
		}
		return 1
	}
	return visit(err)
}

func hasWork(output *model.ScanResult) bool {
	if output == nil {
		return false
	}
	if len(output.Findings) > 0 || output.Stats.RequestsSent > 0 || output.Stats.PayloadsSent > 0 || output.Stats.Status == model.ScanPartial {
		return true
	}
	for _, coverage := range output.Stats.Coverage {
		if coverage.Started > 0 {
			return true
		}
	}
	return false
}

func invoke(ctx context.Context, module Module, target model.Target) (result *model.ScanResult, err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("detector panic: %v", value)
		}
	}()
	return module.Run(ctx, target)
}

func invokeCheck(ctx context.Context, module Module, target model.Target) (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("detector preflight panic: %v", value)
		}
	}()
	return module.Check(ctx, target)
}
