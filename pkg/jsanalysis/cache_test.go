package jsanalysis

import (
	"fmt"
	"sync"
	"testing"
)

func TestCacheIsolationAndBounds(t *testing.T) {
	c := parseCache{maxBytes: 2048}
	source := `export const x='value'; alert(1);`
	a := c.parse(source, ModuleMode)
	if a.Error != "" || len(a.Spans) == 0 || len(a.Calls) == 0 {
		t.Fatalf("parse failed: %+v", a)
	}
	a.Spans[0].Kind = Code
	a.Calls[0].Start = -1
	b := c.parse(source, ModuleMode)
	if b.Spans[0].Kind != String || b.Calls[0].Start < 0 {
		t.Fatal("cached evidence mutated by caller")
	}
	if c.parse(source, ScriptMode).Error == "" {
		t.Fatal("cache mixed source modes")
	}
	for i := 0; i < 300; i++ {
		c.parse(fmt.Sprintf("const x=%d;", i), ScriptMode)
	}
	if c.bytes > c.maxBytes || len(c.entries) > 256 || c.lru.Len() != len(c.entries) {
		t.Fatalf("cache bounds violated bytes=%d entries=%d", c.bytes, len(c.entries))
	}
	if a := c.parse(source, ModuleMode); a.Error != "" || a.Spans[0].Kind != String {
		t.Fatal("eviction changed analysis")
	}
	large := parseCache{maxBytes: 1}
	large.parse(source, ModuleMode)
	if len(large.entries) != 0 || large.bytes != 0 {
		t.Fatal("oversized entry retained")
	}
}

func TestConcurrentCacheCopies(t *testing.T) {
	c := parseCache{maxBytes: 8192}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				a := c.parse(`export const x='value'; alert(1);`, ModuleMode)
				if a.Error != "" || a.Spans[0].Kind != String {
					t.Errorf("corrupt analysis: %+v", a)
					return
				}
				a.Spans[0].Kind = Unknown
				a.Calls[0].Start = -1
			}
		}()
	}
	wg.Wait()
}
