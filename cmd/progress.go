package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
)

// startProgress owns its output goroutine; stop waits before results are printed.
// Redirected stderr receives periodic lines, while terminals update one line.
func startProgress(ctx context.Context, out io.Writer, terminal bool, interval time.Duration) (context.Context, func()) {
	var mu sync.Mutex
	current := model.Progress{Stage: "preparing"}
	ctx = model.WithProgress(ctx, func(next model.Progress) {
		mu.Lock()
		defer mu.Unlock()
		if next.Stage == current.Stage && next.Total == current.Total && next.Completed < current.Completed {
			return
		}
		current = next
	})
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	started := time.Now()
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		width := 0
		render := func() {
			mu.Lock()
			snapshot := current
			mu.Unlock()
			line := progressLine(snapshot, time.Since(started))
			if terminal {
				fmt.Fprintf(out, "\r%s%s", line, strings.Repeat(" ", max(0, width-len(line))))
				width = len(line)
			} else {
				fmt.Fprintln(out, line)
			}
		}
		render()
		for {
			select {
			case <-ticker.C:
				render()
			case <-stop:
				if terminal {
					fmt.Fprintf(out, "\r%s\r", strings.Repeat(" ", width))
				}
				return
			}
		}
	}()
	return ctx, func() { once.Do(func() { close(stop); <-done }) }
}

func progressLine(p model.Progress, elapsed time.Duration) string {
	stage := stripANSI(p.Stage)
	if p.Total > 0 {
		completed := min(max(0, p.Completed), p.Total)
		filled := int(float64(completed) / float64(p.Total) * 16)
		return fmt.Sprintf("[%s%s] %s %d/%d | elapsed %s", strings.Repeat("=", filled), strings.Repeat(".", 16-filled), stage, completed, p.Total, elapsed.Truncate(time.Second))
	}
	return fmt.Sprintf("[working] %s | elapsed %s", stage, elapsed.Truncate(time.Second))
}
