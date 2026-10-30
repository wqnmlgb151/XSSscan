package jsanalysis

import (
	"container/list"
	"crypto/sha256"
	"slices"
	"sync"
)

// Cache only bounded source-independent spans and diagnostics, never source text
// or AST objects. Copies prevent callers from mutating another scan's evidence.
type parseKey struct {
	digest [32]byte
	mode   SourceMode
}
type cacheEntry struct {
	key      parseKey
	analysis Analysis
	bytes    int
}
type parseCache struct {
	mu       sync.Mutex
	entries  map[parseKey]*list.Element
	lru      list.List
	bytes    int
	maxBytes int
	pending  map[parseKey]*parseFlight
}

type parseFlight struct {
	done     chan struct{}
	analysis Analysis
}

var parsedScripts = parseCache{maxBytes: 8 * 1024 * 1024}

func cloneAnalysis(a Analysis) Analysis {
	a.Spans = slices.Clone(a.Spans)
	a.Calls = slices.Clone(a.Calls)
	a.Flows = slices.Clone(a.Flows)
	return a
}

func (c *parseCache) parse(source string, mode SourceMode) Analysis {
	key := parseKey{sha256.Sum256([]byte(source)), mode}
	c.mu.Lock()
	if entry := c.entries[key]; entry != nil {
		c.lru.MoveToFront(entry)
		analysis := entry.Value.(cacheEntry).analysis
		c.mu.Unlock()
		return cloneAnalysis(analysis)
	}
	if flight := c.pending[key]; flight != nil {
		c.mu.Unlock()
		<-flight.done
		return cloneAnalysis(flight.analysis)
	}
	if c.pending == nil {
		c.pending = make(map[parseKey]*parseFlight)
	}
	flight := &parseFlight{done: make(chan struct{})}
	c.pending[key] = flight
	c.mu.Unlock()
	a := parseUncached(source, mode)
	c.mu.Lock()
	defer c.mu.Unlock()
	// Publish even non-cacheable results. Channel close synchronizes waiters;
	// every caller receives independent evidence slices.
	flight.analysis = cloneAnalysis(a)
	delete(c.pending, key)
	defer close(flight.done)
	// Span has two ints and two strings (48 bytes on 64-bit), plus bounded
	// map/list/key overhead. Error text and each slice are accounted for.
	size := 256 + len(a.Error) + len(a.FlowError) + 64*(len(a.Spans)+len(a.Calls))
	for _, f := range a.Flows {
		size += 128 + len(f.Source.Kind) + len(f.Source.Key) + len(f.Sink)
	}
	if size > c.maxBytes {
		return a
	}
	if c.entries == nil {
		c.entries = make(map[parseKey]*list.Element)
	}
	if c.entries[key] != nil {
		return a
	}
	for c.lru.Len() >= 256 || c.bytes+size > c.maxBytes {
		old := c.lru.Back()
		if old == nil {
			break
		}
		entry := old.Value.(cacheEntry)
		delete(c.entries, entry.key)
		c.bytes -= entry.bytes
		c.lru.Remove(old)
	}
	c.entries[key] = c.lru.PushFront(cacheEntry{key, flight.analysis, size})
	c.bytes += size
	return a
}
