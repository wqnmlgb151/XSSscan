package blind

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/callback"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/test/testenv"
)

func TestBlindCorrelationControls(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	t.Cleanup(func() { ssrfguard.AllowPrivate = old })
	for _, tc := range []struct {
		name       string
		correlated bool
		referer    string
		confidence float64
	}{
		{"unrelated", false, "", 0}, {"correlated", true, "", .85}, {"foreign-referer", true, "http://127.0.0.2/", .4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var observed []callback.Callback
			token := regexp.MustCompile(`xsscan=([a-z0-9]+)`)
			server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if match := token.FindStringSubmatch(r.URL.Query().Get("q")); len(match) > 0 {
					query := "xsscan=unrelated"
					if tc.correlated {
						query = "xsscan=" + match[1]
					}
					mu.Lock()
					observed = append(observed, callback.Callback{Query: query, Referer: tc.referer})
					mu.Unlock()
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			scan := New(server.Client(), Config{Callback: "http://callback.test/", Observe: func(context.Context) ([]callback.Callback, error) {
				mu.Lock()
				defer mu.Unlock()
				return append([]callback.Callback(nil), observed...), nil
			}})
			result, err := scan.Scan(context.Background(), model.Target{URL: server.URL + "/?q=x"})
			if err != nil || result.Stats.Status != model.ScanCompleted || result.Stats.PayloadsSent == 0 {
				t.Fatalf("incomplete: %+v %v", result, err)
			}
			if (len(result.Findings) > 0) != tc.correlated {
				t.Fatalf("correlation verdict: %+v", result.Findings)
			}
			for _, f := range result.Findings {
				if f.ExecutionVerified || f.Confidence != tc.confidence {
					t.Fatalf("callback overstated: %+v", f)
				}
			}
		})
	}
}

func TestBlindObservationDeadlineAndCancellation(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	t.Cleanup(func() { ssrfguard.AllowPrivate = old })
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	for _, deadline := range []bool{true, false} {
		t.Run(map[bool]string{true: "deadline", false: "cancellation"}[deadline], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var expected error = context.Canceled
			if deadline {
				expected = context.DeadlineExceeded
			}
			observeEntered := false
			scan := New(server.Client(), Config{Callback: "http://callback.test/", Observe: func(ctx context.Context) ([]callback.Callback, error) {
				observeEntered = true
				if deadline {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
					defer stop()
				} else {
					cancel()
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}})
			result, err := scan.Scan(ctx, model.Target{URL: server.URL + "/?q=x"})
			if !observeEntered || !errors.Is(err, expected) || result.Stats.Status == model.ScanCompleted || len(result.Findings) != 0 {
				t.Fatalf("lost cancellation: %+v %v", result, err)
			}
		})
	}
}
