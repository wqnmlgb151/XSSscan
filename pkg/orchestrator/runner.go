package orchestrator

import (
	"context"
	"errors"
	"fmt"
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
					if output != nil && (len(output.Findings) > 0 || output.Stats.Status == model.ScanPartial) {
						status = model.ScanPartial
					}
				} else if output.Stats.Status != "" {
					status = output.Stats.Status
				}
			}
			if moduleCtx.Err() != nil {
				err = errors.Join(err, moduleCtx.Err())
				status = model.ScanFailed
				if output != nil && len(output.Findings) > 0 {
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
			if len(mr.Issues) == 0 {
				mr.Issues = []model.ScanIssue{{Target: target.URL, Stage: string(kind), Message: err.Error()}}
			}
			problems = append(problems, fmt.Errorf("%s: %w", kind, err))
		} else if status != model.ScanCompleted {
			mr.Reason = "detector did not complete"
			problems = append(problems, fmt.Errorf("%s: %s", kind, status))
		}
		result.Stats.Issues = append(result.Stats.Issues, mr.Issues...)
		result.Stats.Errors += len(mr.Issues)
		result.Stats.Modules = append(result.Stats.Modules, mr)
		result.Stats.Status = model.MergeStatus(result.Stats.Status, status)
	}
	return result, errors.Join(problems...)
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
