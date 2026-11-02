package requestbudget

import (
	"context"
	"sync"
	"testing"
)

func TestConcurrentIndependentBudgets(t *testing.T) {
	m := New(7, 11)
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { m.HTTP.Take(); m.Browser.Take() })
	}
	wg.Wait()
	if m.HTTP.Count() != 7 || m.HTTP.Denied() != 93 || m.Browser.Count() != 11 || m.Browser.Denied() != 89 {
		t.Fatal("incorrect concurrent reservations")
	}
	if FromContext(WithMeter(context.Background(), m)) != m {
		t.Fatal("lost meter")
	}
}
func TestUnlimitedBatchIsolation(t *testing.T) {
	a, b := New(0, 0), New(1, 1)
	for range 100 {
		if !a.HTTP.Take() || !a.Browser.Take() {
			t.Fatal("unlimited rejected")
		}
	}
	if b.HTTP.Count() != 0 || b.Browser.Count() != 0 {
		t.Fatal("batch state leaked")
	}
}

func BenchmarkCounterTake(b *testing.B) {
	c := NewCounter(0)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Take()
		}
	})
}
