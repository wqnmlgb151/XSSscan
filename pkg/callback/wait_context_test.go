package callback

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWaitForContextCancellation(t *testing.T) {
	s := NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.WaitForContext(ctx, 1, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled callback wait blocked")
	}
}

func TestObserveWindowDoesNotStopAtFirstCallback(t *testing.T) {
	s := NewServer("127.0.0.1:0")
	// Feed the handler directly; no browser or external callback service needed.
	go func() {
		time.Sleep(10 * time.Millisecond)
		s.handleCallback(httptest.NewRecorder(), httptest.NewRequest("GET", "http://local/?xsscan=first", nil))
		time.Sleep(20 * time.Millisecond)
		s.handleCallback(httptest.NewRecorder(), httptest.NewRequest("GET", "http://local/?xsscan=second", nil))
	}()
	callbacks := s.ObserveWindow(context.Background(), 60*time.Millisecond)
	if len(callbacks) != 2 {
		t.Fatalf("late callback lost: %+v", callbacks)
	}
}
