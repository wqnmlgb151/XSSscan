package model

import "context"

// Progress describes completed work within a stage, not an estimated scan ETA.
type Progress struct {
	Stage     string
	Completed int
	Total     int
}

type progressKey struct{}

// WithProgress attaches an optional observer. The observer must be concurrency-safe.
func WithProgress(ctx context.Context, observe func(Progress)) context.Context {
	return context.WithValue(ctx, progressKey{}, observe)
}

func ReportProgress(ctx context.Context, stage string, completed, total int) {
	if observe, ok := ctx.Value(progressKey{}).(func(Progress)); ok && observe != nil {
		observe(Progress{Stage: stage, Completed: completed, Total: total})
	}
}
