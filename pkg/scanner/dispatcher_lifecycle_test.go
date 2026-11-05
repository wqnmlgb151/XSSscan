package scanner

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"testing"
	"time"
)

func TestDispatcherCancellationWithMoreRelaysThanBuffer(t *testing.T) {
	ctx, cancel := context.WithCancel(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	defer cancel()
	const count = 80
	paths := make([]scheduledTask, count)
	in := make(chan dispatchItem[int], count)
	for i := range count {
		id := pathID(fmt.Sprint(i))
		paths[i] = scheduledTask{path: id, index: i}
		in <- dispatchItem[int]{item: i, path: id, done: make(chan struct{})}
	}
	close(in)
	s, err := newScheduler(paths, 1)
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan dispatchItem[int], count)
	done := startPathDispatcher(ctx, in, out, s)
	for range count {
		select {
		case <-out:
		case <-time.After(5 * time.Second):
			t.Fatal("independent work not dispatched")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay workers did not exit after cancellation")
	}
}

func TestDispatcherDrainsProducerAfterPathProof(t *testing.T) {
	ctx, cancel := context.WithCancel(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	defer cancel()
	proven := newAtomicPathSet()
	s, err := newSchedulerWithProof([]scheduledTask{{path: "a", index: 0}, {path: "a", index: 1}}, 1, proven)
	if err != nil {
		t.Fatal(err)
	}
	in, out := make(chan dispatchItem[int]), make(chan dispatchItem[int])
	allowSecond, producerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(producerDone)
		defer close(in)
		select {
		case in <- dispatchItem[int]{item: 0, path: "a", done: make(chan struct{})}:
		case <-ctx.Done():
			return
		}
		select {
		case <-allowSecond:
		case <-ctx.Done():
			return
		}
		select {
		case in <- dispatchItem[int]{item: 1, path: "a", done: make(chan struct{})}:
		case <-ctx.Done():
		}
	}()
	done := startPathDispatcher(ctx, in, out, s)
	t.Cleanup(func() { cancel(); <-producerDone; <-done })
	select {
	case first := <-out:
		proven.add("a")
		close(first.done)
	case <-time.After(5 * time.Second):
		t.Fatal("first candidate not dispatched")
	}
	select {
	case <-done:
		t.Fatal("dispatcher finished before draining its live producer")
	case <-time.After(50 * time.Millisecond):
	}
	close(allowSecond)
	select {
	case <-producerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("producer leaked after convergence")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatcher did not finish")
	}
	if s.skippedByProof() != 1 {
		t.Fatalf("remaining coverage lost: %+v", s.stats())
	}
}
