package jsanalysis

import (
	"strings"
	"sync"
	"testing"
)

func TestConcurrentFlightEvidenceIsolation(t *testing.T) {
	source := strings.Repeat("void 'literal';\n", 800) + `el.innerHTML=localStorage.getItem('template')`
	c := parseCache{maxBytes: 8 * 1024 * 1024}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			a := c.parse(source, ScriptMode)
			if a.Error != "" || len(a.Flows) != 1 || a.Flows[0].Source.Key != "template" {
				t.Errorf("cross-caller evidence: %+v", a)
				return
			}
			a.Flows[0].Source.Key = "changed"
			a.Spans[0].Start = -1
		}()
	}
	close(start)
	wg.Wait()
	a := c.parse(source, ScriptMode)
	if a.Flows[0].Source.Key != "template" || a.Spans[0].Start < 0 || len(c.pending) != 0 {
		t.Fatal("flight/cache leaked mutable evidence")
	}
}

func BenchmarkConcurrentColdScript(b *testing.B) {
	source := strings.Repeat("void 'literal';\n", 800) + "alert(1)"
	b.ReportAllocs()
	for b.Loop() {
		c := parseCache{maxBytes: 8 * 1024 * 1024}
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 16 {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; c.parse(source, ScriptMode) }()
		}
		close(start)
		wg.Wait()
	}
}
