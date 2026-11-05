package main

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func recordScanIssue(stats *model.ScanStats, target, stage string, err error) {
	if err == nil {
		return
	}
	status := model.ScanFailed
	if errors.Is(err, context.Canceled) {
		status = model.ScanCanceled
	}
	stats.Status = model.MergeStatus(stats.Status, status)
	stats.Errors++
	stats.Issues = append(stats.Issues, model.ScanIssue{Target: target, Stage: stage, Message: err.Error()})
}

func scanURLForIssue(urls []string) string {
	if len(urls) > 0 {
		return urls[len(urls)-1]
	}
	return ""
}

type batchTransport struct {
	base  http.RoundTripper
	count *atomic.Int64
}

func (t batchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.count.Add(1)
	return t.base.RoundTrip(req)
}
