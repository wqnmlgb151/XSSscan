package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xsscan/xsscan/pkg/execverify"
	"github.com/xsscan/xsscan/pkg/model"
)

type candidateVerifier interface {
	VerifyFinding(context.Context, model.Finding, model.Target) (*execverify.ExecutionResult, error)
	Close() error
}

// adaptiveVerification belongs to one Run. Workers hold their path slot until
// check returns; finish groups already checked evidence without replaying it.
type adaptiveVerification struct {
	engine                                        *Engine
	target                                        model.Target
	open                                          func() (candidateVerifier, error)
	once, closeOnce                               sync.Once
	verifier                                      candidateVerifier
	initErr                                       error
	slots                                         chan struct{}
	planned, started, completed, failed, canceled atomic.Int64
}

func newAdaptiveVerification(ctx context.Context, e *Engine, target model.Target) *adaptiveVerification {
	s := &adaptiveVerification{engine: e, target: target, slots: make(chan struct{}, 4)}
	s.open = func() (candidateVerifier, error) {
		timeout := e.config.VerifyTimeout
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		return execverify.NewVerifierWithAuth(ctx, timeout, buildAuthState(target))
	}
	return s
}

func (s *adaptiveVerification) check(ctx context.Context, f *model.Finding) {
	// Unsupported alternatives are handled after grouping: they must not make a
	// proven group incomplete merely because no browser dialog can be instrumented.
	if !execverify.SupportsDialogVerification(f.Payload) {
		return
	}
	s.planned.Add(1)
	if err := ctx.Err(); err != nil {
		s.engine.applyVerificationError(f, nil, err)
		s.engine.recordRunError("execution", err)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		s.engine.applyVerificationError(f, nil, ctx.Err())
		s.engine.recordRunError("execution", ctx.Err())
		return
	}
	s.once.Do(func() {
		func() {
			defer func() {
				if p := recover(); p != nil {
					s.initErr = fmt.Errorf("execution verifier setup panic: %v", p)
				}
			}()
			s.verifier, s.initErr = s.open()
			if s.verifier == nil && s.initErr == nil {
				s.initErr = fmt.Errorf("execution verifier setup returned no verifier")
			}
		}()
		if s.initErr != nil {
			s.engine.recordRunError("execution", s.initErr)
		}
	})
	if s.initErr != nil {
		s.engine.applyVerificationError(f, nil, s.initErr)
		return
	}
	if err := ctx.Err(); err != nil {
		s.engine.applyVerificationError(f, nil, err)
		s.engine.recordRunError("execution", err)
		return
	}
	s.started.Add(1)
	result, err := callExecutionVerifier(ctx, *f, s.target, s.verifier.VerifyFinding)
	if result == nil && err == nil {
		err = fmt.Errorf("execution verifier returned no result")
	}
	if err != nil {
		if ctx.Err() != nil {
			s.canceled.Add(1)
		} else {
			s.failed.Add(1)
		}
		s.engine.applyVerificationError(f, result, err)
		s.engine.recordRunError("execution", err)
	} else {
		s.completed.Add(1)
		s.engine.applyVerificationResult(f, result)
	}
}

func (s *adaptiveVerification) finish(findings []model.Finding) []model.Finding {
	var out []model.Finding
	for _, group := range groupVerificationCandidates(findings) {
		var proof *model.Finding
		for i := range group {
			if group[i].ExecutionVerified && (proof == nil || betterFinding(proof, &group[i])) {
				proof = &group[i]
			}
		}
		if proof != nil {
			winner := *proof
			for _, f := range group {
				winner.Payloads = append(winner.Payloads, f.Payload)
			}
			out = append(out, winner)
			continue
		}
		var unsupportedErr error
		for i := range group {
			if !execverify.SupportsDialogVerification(group[i].Payload) {
				if unsupportedErr == nil {
					unsupportedErr = fmt.Errorf("candidate in parameter %q has no supported dialog call for execution verification", group[i].Parameter)
					s.engine.recordRunError("execution", unsupportedErr)
				}
				s.engine.applyVerificationError(&group[i], nil, unsupportedErr)
			}
		}
		out = append(out, group...)
	}
	return out
}

// Close runs after HTTP workers have joined, including cancellation. Counts cover
// eligible checks actually requested during dispatch; future findings are unknown.
func (s *adaptiveVerification) Close() {
	s.closeOnce.Do(func() {
		if s.verifier != nil {
			s.engine.recordRunError("execution cleanup", s.verifier.Close())
		}
		s.engine.recordCoverage(model.CheckCoverage{Stage: "adaptive_verification_attempts", PlannedKnown: false,
			Planned: int(s.planned.Load()), Started: int(s.started.Load()), Completed: int(s.completed.Load()),
			Failed: int(s.failed.Load()), Canceled: int(s.canceled.Load()), NotStarted: int(s.planned.Load() - s.started.Load())})
	})
}
