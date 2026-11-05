package scanner

import (
	"errors"
	"github.com/wqnmlgb151/XSSscan/pkg/execverify"
	allocopts "github.com/wqnmlgb151/XSSscan/pkg/internal/chromedp"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"testing"
)

func TestCleanupErrorPreservesObservedExecution(t *testing.T) {
	e := NewEngine(Config{}, nil, nil)
	proof := &execverify.ExecutionResult{Executed: true, Confidence: .95, DialogMessage: "token"}
	for _, mixed := range []bool{false, true} {
		f := model.Finding{Confidence: .8}
		var err error = &allocopts.CleanupError{Cause: errors.New("dispose failed")}
		if mixed {
			err = errors.Join(err, errors.New("protocol failed"))
		}
		e.applyVerificationError(&f, proof, err)
		if f.ExecutionVerified == mixed || f.Evidence.VerificationError == "" {
			t.Fatalf("incorrect evidence disposition: %+v", f)
		}
	}
}
