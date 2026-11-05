package httpclient

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
)

func TestConcurrentClientPoliciesRemainIndependent(t *testing.T) {
	var hits atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	allowed := NewClient(time.Second, nil, ssrfguard.Policy{AllowPrivate: true})
	blocked := NewClient(time.Second, nil, ssrfguard.Policy{})
	defer allowed.CloseIdleConnections()
	defer blocked.CloseIdleConnections()
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for _, client := range []*http.Client{allowed, blocked} {
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
				response, err := client.Do(req)
				if response != nil {
					response.Body.Close()
				}
				if client == allowed && err != nil {
					t.Errorf("allowed client rejected: %v", err)
				}
				if client == blocked && err == nil {
					t.Error("strict policy bypassed")
				}
			}
		}()
	}
	workers.Wait()
	if hits.Load() != 20 {
		t.Fatalf("policy contamination, target hits=%d", hits.Load())
	}
}

func TestClientPolicySnapshotsCallerSlice(t *testing.T) {
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	policies := []ssrfguard.Policy{{}}
	client := NewClient(time.Second, nil, policies...)
	defer client.CloseIdleConnections()
	policies[0].AllowPrivate = true
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("caller mutated an existing client's policy")
	}
}
