package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
)

// drain pulls every task the scheduler is willing to hand out, calling done()
// after each one, and returns the dispatch order plus the peak in-flight counts.
func drain(t *testing.T, s *scheduler, maxIter int) ([]scheduledTask, map[pathID]int) {
	t.Helper()
	var order []scheduledTask
	peak := map[pathID]int{}
	live := map[pathID]int{}
	for i := 0; i < maxIter; i++ {
		task, ok := s.next()
		if !ok {
			return order, peak
		}
		order = append(order, task)
		live[task.path]++
		if live[task.path] > peak[task.path] {
			peak[task.path] = live[task.path]
		}
		// Complete immediately so the loop measures ordering, not capacity.
		s.done(task.path)
		live[task.path]--
	}
	t.Fatalf("scheduler did not exhaust after %d iterations", maxIter)
	return nil, nil
}

// A single path must never have more than maxPerPath tasks in flight before any
// feedback arrives. This is the property the plan calls "每路径初始最多1个在途决策
// 任务，防止反馈到来前已发送大量等价候选".
func TestSchedulerBoundsInFlightPerPath(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "a", index: 2},
	}
	s, err := newScheduler(tasks, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Without completing anything, exactly one task for path "a" is available.
	first, ok := s.next()
	if !ok {
		t.Fatal("expected the first task")
	}
	if _, ok := s.next(); ok {
		t.Fatal("a second task for the same path was handed out while one was in flight")
	}
	// Completing it frees the slot.
	s.done(first.path)
	if _, ok := s.next(); !ok {
		t.Fatal("no task available after the in-flight slot was released")
	}
}

// maxPerPath <= 0 must reproduce the exhaustive ordering: no concurrency bound.
func TestSchedulerUnboundedWhenLimitDisabled(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "a", index: 2},
	}
	s, err := newScheduler(tasks, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for {
		if _, ok := s.next(); !ok {
			break
		}
		seen++
	}
	if seen != 3 {
		t.Fatalf("expected all 3 tasks dispatchable without a bound, got %d", seen)
	}
}

// Independent paths must rotate, so a path with many candidates cannot starve a
// path with few. The plan requires fair exploration of every candidate family.
func TestSchedulerRotatesAcrossPaths(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "a", index: 2}, {path: "a", index: 3},
		{path: "b", index: 4},
		{path: "c", index: 5},
	}
	s, err := newScheduler(tasks, 1)
	if err != nil {
		t.Fatal(err)
	}
	order, _ := drain(t, s, 10)
	if len(order) != 6 {
		t.Fatalf("expected 6 dispatches, got %d", len(order))
	}
	// The two single-candidate paths must be served before path "a" is drained:
	// their first dispatch has to appear within the first three tasks.
	firstThree := map[pathID]bool{}
	for _, task := range order[:3] {
		firstThree[task.path] = true
	}
	if !firstThree["b"] || !firstThree["c"] {
		t.Fatalf("rotation starved a small path: first three dispatches were %v", order[:3])
	}
}

// Rotation must be deterministic for a given input, so a fixed-concurrency run
// is reproducible and its dispatch order can be diffed.
func TestSchedulerIsDeterministic(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1},
		{path: "b", index: 2}, {path: "b", index: 3},
		{path: "c", index: 4},
	}
	run := func() []scheduledTask {
		s, err := newScheduler(tasks, 1)
		if err != nil {
			t.Fatal(err)
		}
		order, _ := drain(t, s, 10)
		return order
	}
	first, second := run(), run()
	if len(first) != len(second) {
		t.Fatalf("dispatch counts differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("dispatch %d differs: %+v vs %+v", i, first[i], second[i])
		}
	}
}

// Progress or completion on one path must never remove work from another path.
// The plan is explicit that a success covers only its own path.
func TestSchedulerDoesNotSuppressOtherPaths(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1},
		{path: "b", index: 2}, {path: "b", index: 3},
	}
	s, err := newScheduler(tasks, 1)
	if err != nil {
		t.Fatal(err)
	}
	before := s.remaining("b")

	// Drive path "a" to completion. Rotation serves "b" too, so complete those
	// dispatches as well; what must not change is how much work "b" still has.
	for s.remaining("a") > 0 {
		task, ok := s.next()
		if !ok {
			t.Fatal("scheduler stalled while path a still had work")
		}
		s.done(task.path)
	}
	if s.remaining("a") != 0 {
		t.Fatalf("path a was not drained: remaining=%d", s.remaining("a"))
	}
	// Path b must still hold every task that was not actually dispatched for it.
	if remaining := s.remaining("b"); remaining > before {
		t.Fatalf("path b gained work: %d -> %d", before, remaining)
	}
	if s.exhausted() != (s.remaining("b") == 0) {
		t.Fatalf("exhaustion disagrees with path b's remaining work: exhausted=%v remaining=%d", s.exhausted(), s.remaining("b"))
	}
}

// Exhaustion is a global property: it must only report true once every path is
// empty, so a caller cannot mistake one finished path for a finished scan.
func TestSchedulerExhaustionRequiresEveryPath(t *testing.T) {
	s, err := newScheduler([]scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1},
		{path: "b", index: 2},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if s.exhausted() {
		t.Fatal("reported exhaustion before any dispatch")
	}

	// Dispatch without completing: one task per path is in flight, so a third
	// dispatch is impossible and the scheduler is not exhausted.
	for i := 0; i < 2; i++ {
		if _, ok := s.next(); !ok {
			t.Fatalf("expected dispatch %d to be available", i)
		}
	}
	if s.exhausted() {
		t.Fatal("reported exhaustion while both paths still had pending work")
	}
}

// A task without a path cannot be placed on the rotation; accepting it silently
// would lose coverage, so construction must fail.
func TestSchedulerRejectsUnattributedTask(t *testing.T) {
	if _, err := newScheduler([]scheduledTask{{path: "", index: 0}}, 1); err == nil {
		t.Fatal("expected an error for a task with no path identity")
	}
}

// An empty task list is not an error; it simply has nothing to dispatch.
func TestSchedulerHandlesEmptyInput(t *testing.T) {
	s, err := newScheduler(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.next(); ok {
		t.Fatal("empty scheduler handed out a task")
	}
	if !s.exhausted() {
		t.Fatal("empty scheduler did not report exhaustion")
	}
}

// done() for an unknown path must be a no-op so a late result from a previous
// run cannot push a counter negative or corrupt current state.
func TestSchedulerDoneIgnoresUnknownPath(t *testing.T) {
	s, err := newScheduler([]scheduledTask{{path: "a", index: 0}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.done("never-seen")
	s.done("a") // not in flight either
	if got := s.inflight["a"]; got != 0 {
		t.Fatalf("in-flight count went negative or changed: %d", got)
	}
}

// The observable bound: with a limit of 1, no path ever exceeds one concurrent
// task, while all tasks still get dispatched.
func TestSchedulerPeakInFlightRespectsLimit(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "a", index: 2},
		{path: "b", index: 3}, {path: "b", index: 4},
	}
	s, err := newScheduler(tasks, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Dispatch everything the scheduler offers without completing, then check
	// each path appears at most once.
	live := map[pathID]int{}
	offered := 0
	for {
		task, ok := s.next()
		if !ok {
			break
		}
		live[task.path]++
		offered++
		if live[task.path] > 1 {
			t.Fatalf("path %q had %d tasks in flight with limit 1", task.path, live[task.path])
		}
	}
	if offered != 2 {
		t.Fatalf("expected one in-flight task per path (2 total), got %d", offered)
	}
}

// stats must report per-path counts for every path, in stable order.
func TestSchedulerStatsCoverEveryPath(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "b", index: 2},
	}
	s, err := newScheduler(tasks, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.next(); !ok {
		t.Fatal("expected a task")
	}
	stats := s.stats()
	if len(stats) != 2 {
		t.Fatalf("expected 2 paths in stats, got %d", len(stats))
	}
	total := 0
	for _, st := range stats {
		total += st.Dispatched + st.Remaining
	}
	if total != 3 {
		t.Fatalf("stats lost tasks: total=%d", total)
	}
}

// --- attribution ---

func TestConvergenceRequiresOneMatchingAnchoredReflection(t *testing.T) {
	body := ctxAt(xctx.ContextHTMLBody, "response_bytes", 10, "", "", "")
	otherBody := ctxAt(xctx.ContextHTMLBody, "response_bytes", 40, "", "", "")
	attr := ctxAt(xctx.ContextHTMLAttrValue, "response_bytes", 80, "input", "value", "'")
	for _, tc := range []struct {
		name     string
		url      string
		contexts []xctx.Context
		context  xctx.ContextType
		want     bool
	}{
		{"unique", "http://example.com/?q=1", []xctx.Context{body}, xctx.ContextHTMLBody, true},
		{"same-type positions", "http://example.com/?q=1", []xctx.Context{body, otherBody}, xctx.ContextHTMLBody, false},
		{"different positions", "http://example.com/?q=1", []xctx.Context{body, attr}, xctx.ContextHTMLBody, false},
		{"unmatched", "http://example.com/?q=1", []xctx.Context{body}, xctx.ContextCSSBlock, false},
		{"unanchored", "http://example.com/?q=1", []xctx.Context{{Type: xctx.ContextHTMLBody}}, xctx.ContextHTMLBody, false},
		{"incomplete", "http://[::1", []xctx.Context{body}, xctx.ContextHTMLBody, false},
		{"missing", "http://example.com/?q=1", nil, xctx.ContextHTMLBody, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := model.Target{URL: tc.url}
			injection := model.InjectionPoint{Target: target, Parameter: model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}, Contexts: tc.contexts}
			tasks, err := buildScheduledTasks(target, injection, []payload.Payload{{Value: "one", Context: tc.context}, {Value: "two", Context: tc.context}})
			if err != nil || len(tasks) != 2 {
				t.Fatalf("candidate lost: %+v %v", tasks, err)
			}
			for _, task := range tasks {
				if task.canConverge != tc.want {
					t.Fatalf("unsafe convergence permission: %+v want %v", task, tc.want)
				}
			}
		})
	}
}

// Payloads must land on the path of the reflection position that produced their
// context, so a payload aimed at one position is not credited to another.
func TestBuildScheduledTasksAttributesByContext(t *testing.T) {
	target := model.Target{URL: "http://example.com/page?q=1"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery},
		Contexts: []xctx.Context{
			ctxAt(xctx.ContextHTMLBody, "response_bytes", 10, "", "", ""),
			ctxAt(xctx.ContextHTMLAttrValue, "response_bytes", 40, "input", "value", "'"),
		},
	}
	payloads := []payload.Payload{
		{Value: "p1", Context: xctx.ContextHTMLBody},
		{Value: "p2", Context: xctx.ContextHTMLAttrValue},
		{Value: "p3", Context: xctx.ContextHTMLBody},
	}
	tasks, err := buildScheduledTasks(target, injection, payloads)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 3 {
		t.Fatalf("expected 3 tasks, got %d", len(tasks))
	}
	if tasks[0].path != tasks[2].path {
		t.Fatal("two payloads with the same context were split across paths")
	}
	if tasks[0].path == tasks[1].path {
		t.Fatal("payloads targeting different reflection positions share a path")
	}
}

// A payload whose context matches no declared position must still be dispatchable;
// dropping it would lose coverage, so it falls back to the input-scoped path.
func TestBuildScheduledTasksFallsBackForUnmatchedContext(t *testing.T) {
	target := model.Target{URL: "http://example.com/page?q=1"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery},
		Contexts:  []xctx.Context{ctxAt(xctx.ContextHTMLBody, "response_bytes", 10, "", "", "")},
	}
	payloads := []payload.Payload{{Value: "p1", Context: xctx.ContextCSSBlock}}
	tasks, err := buildScheduledTasks(target, injection, payloads)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].path == "" {
		t.Fatalf("unmatched payload was not given a fallback path: %+v", tasks)
	}
}

// An incomplete input identity must collapse to a single path: it must not be
// used to separate positions, because the separation would be unverifiable.
func TestBuildScheduledTasksSinglePathWhenIdentityIncomplete(t *testing.T) {
	target := model.Target{URL: "http://[::1"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery},
		Contexts: []xctx.Context{
			ctxAt(xctx.ContextHTMLBody, "response_bytes", 10, "", "", ""),
			ctxAt(xctx.ContextHTMLAttrValue, "response_bytes", 40, "input", "value", "'"),
		},
	}
	payloads := []payload.Payload{
		{Value: "p1", Context: xctx.ContextHTMLBody},
		{Value: "p2", Context: xctx.ContextHTMLAttrValue},
	}
	tasks, err := buildScheduledTasks(target, injection, payloads)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(tasks))
	}
	if tasks[0].path != tasks[1].path {
		t.Fatal("incomplete identity still separated positions")
	}
}

// Every task must be dispatchable: attribution must not drop or duplicate any
// payload index.
func TestBuildScheduledTasksPreservesEveryPayload(t *testing.T) {
	target := model.Target{URL: "http://example.com/page?q=1"}
	injection := model.InjectionPoint{
		Target:    target,
		Parameter: model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery},
		Contexts: []xctx.Context{
			ctxAt(xctx.ContextHTMLBody, "response_bytes", 10, "", "", ""),
			ctxAt(xctx.ContextJSString, "document_bytes", 80, "", "", "'"),
		},
	}
	payloads := []payload.Payload{
		{Value: "p1", Context: xctx.ContextHTMLBody},
		{Value: "p2", Context: xctx.ContextJSString},
		{Value: "p3", Context: xctx.ContextJSString},
		{Value: "p4", Context: xctx.ContextCSSValue},
	}
	tasks, err := buildScheduledTasks(target, injection, payloads)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != len(payloads) {
		t.Fatalf("expected %d tasks, got %d", len(payloads), len(tasks))
	}
	seen := make(map[int]bool, len(tasks))
	for _, task := range tasks {
		if seen[task.index] {
			t.Fatalf("payload index %d attributed twice", task.index)
		}
		seen[task.index] = true
	}
	for i := range payloads {
		if !seen[i] {
			t.Fatalf("payload index %d was dropped", i)
		}
	}
}

// newDispatcherFixture builds the channels a dispatcher test needs. Items are
// pre-loaded and the input closed, so the dispatcher never waits for more input.
func newDispatcherFixture(values []int, paths []scheduledTask) (chan dispatchItem[int], chan dispatchItem[int]) {
	in := make(chan dispatchItem[int], len(values))
	for i, v := range values {
		in <- dispatchItem[int]{item: v, path: paths[i].path, done: make(chan struct{})}
	}
	close(in)
	return in, make(chan dispatchItem[int])
}

// The coverage-preservation proof for the dispatcher: every item handed to it
// must arrive at the output exactly once, even though the scheduler reorders them
// and bounds how many are in flight per path. A dropped or duplicated item here
// would be a silent coverage change, which is the failure mode the plan forbids.
func TestDispatcherDeliversEveryItemExactlyOnce(t *testing.T) {
	items := []int{0, 1, 2, 3, 4, 5}
	paths := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "a", index: 2},
		{path: "b", index: 3},
		{path: "c", index: 4}, {path: "c", index: 5},
	}
	s, err := newScheduler(paths, 1)
	if err != nil {
		t.Fatal(err)
	}

	in, out := newDispatcherFixture(items, paths)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dispatcherDone := startPathDispatcher(ctx, in, out, s)

	// Consume the output like a worker would: finish the item, which closes its
	// completion channel and frees that path's slot.
	seen := map[int]int{}
	for entry := range out {
		seen[entry.item]++
		close(entry.done)
	}

	select {
	case <-dispatcherDone:
	case <-ctx.Done():
		t.Fatal("dispatcher did not terminate; it is deadlocked")
	}

	if len(seen) != len(items) {
		t.Fatalf("dispatcher delivered %d distinct items, want %d", len(seen), len(items))
	}
	for _, it := range items {
		switch seen[it] {
		case 1:
		case 0:
			t.Errorf("item %d was never dispatched: coverage lost", it)
		default:
			t.Errorf("item %d was dispatched %d times", it, seen[it])
		}
	}
}

// The dispatcher must terminate when the context is cancelled rather than leaving
// a goroutine blocked forever.
func TestDispatcherStopsOnCancel(t *testing.T) {
	items := []int{0, 1, 2}
	paths := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "a", index: 2},
	}
	s, err := newScheduler(paths, 1)
	if err != nil {
		t.Fatal(err)
	}
	in, out := newDispatcherFixture(items, paths)

	ctx, cancel := context.WithCancel(context.Background())
	done := startPathDispatcher(ctx, in, out, s)
	// Drain whatever was dispatched, then cancel without releasing anything:
	// the bound stops further dispatch and the dispatcher must still exit.
	go func() {
		for range out {
		}
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatcher ignored cancellation")
	}
}

// A dispatcher whose items arrive slowly must still dispatch everything, in
// scheduler order, rather than giving up because the schedule names indices it has
// not received yet. This is the regression guard for a dispatcher that burned
// through its schedule while the item queue was still filling.
func TestDispatcherHandlesSlowArrival(t *testing.T) {
	const n = 12
	paths := make([]scheduledTask, 0, n)
	for i := 0; i < n; i++ {
		// Two paths, so the rotation visits both and the bound of 1 applies.
		paths = append(paths, scheduledTask{path: pathID(string(rune('a' + i%2))), index: i})
	}
	s, err := newScheduler(paths, 1)
	if err != nil {
		t.Fatal(err)
	}

	in := make(chan dispatchItem[int])
	out := make(chan dispatchItem[int])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Feed one item at a time with a pause, so the dispatcher makes several passes
	// with a partially filled queue.
	go func() {
		defer close(in)
		for i := 0; i < n; i++ {
			in <- dispatchItem[int]{item: i, path: paths[i].path, done: make(chan struct{})}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	done := startPathDispatcher(ctx, in, out, s)
	seen := map[int]int{}
	for entry := range out {
		seen[entry.item]++
		close(entry.done)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("dispatcher did not terminate with slow input")
	}
	if len(seen) != n {
		t.Fatalf("slow arrival lost items: delivered %d of %d", len(seen), n)
	}
}

// The coverage summary is counts-only and must never render as a percentage or
// a safety claim; the plan forbids presenting path counts as coverage.
func TestFormatPathStatsIsCountsOnly(t *testing.T) {
	got := formatPathStats([]pathStats{{ID: "x", Dispatched: 2, Remaining: 1}}, 10)
	if strings.Contains(got, "%") {
		t.Fatalf("summary looks like a coverage percentage: %q", got)
	}
	if !strings.Contains(got, "dispatched=2") || !strings.Contains(got, "remaining=1") {
		t.Fatalf("summary lost counts: %q", got)
	}
}

// --- execution-proof convergence ---

// A proven path must stop being scheduled, and a proof for one path must not touch
// another. The second half is the constraint the plan states most firmly: a success
// covers only its own path.
func TestProvenPathStopsSchedulingOthersUnaffected(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "a", index: 2},
		{path: "b", index: 3}, {path: "b", index: 4},
	}
	proven := newAtomicPathSet()
	s, err := newSchedulerWithProof(tasks, 1, proven)
	if err != nil {
		t.Fatal(err)
	}

	// Settle path "a" before anything is dispatched.
	s.markPathProven("a")

	var got []scheduledTask
	for {
		task, ok := s.next()
		if !ok {
			break
		}
		got = append(got, task)
		s.done(task.path)
	}
	for _, task := range got {
		if task.path == "a" {
			t.Fatalf("a proven path was still scheduled: %+v", task)
		}
	}
	if remaining := s.remaining("b"); remaining != 0 {
		t.Fatalf("path b did not complete: remaining=%d", remaining)
	}
	if !s.exhausted() {
		t.Fatal("scheduler did not report exhaustion after the proven path was skipped")
	}
	if skipped := s.skippedByProof(); skipped != 3 {
		t.Fatalf("expected 3 candidates skipped by proof, got %d", skipped)
	}
}

// A proof arriving after dispatch started must stop the remaining candidates of that
// path only. This is the mid-flight case the adaptive strategy exists for.
func TestProvenMidFlightStopsRemainingCandidates(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "a", index: 2},
		{path: "b", index: 3}, {path: "b", index: 4},
	}
	proven := newAtomicPathSet()
	s, err := newSchedulerWithProof(tasks, 1, proven)
	if err != nil {
		t.Fatal(err)
	}

	first, ok := s.next()
	if !ok {
		t.Fatal("expected a first dispatch")
	}
	s.done(first.path)
	// The proof lands while the scan is running.
	s.markPathProven("a")

	seen := map[pathID]int{}
	for {
		task, ok := s.next()
		if !ok {
			break
		}
		seen[task.path]++
		s.done(task.path)
	}
	if seen["a"] > 0 {
		t.Fatalf("path a kept dispatching after its proof: %d more", seen["a"])
	}
	if seen["b"] != 2 {
		t.Fatalf("path b lost candidates because another path was proven: dispatched %d of 2", seen["b"])
	}
}

// Exhaustion must treat a proven path's leftover candidates as finished, otherwise
// the dispatcher would wait for work it is right not to send.
func TestExhaustionIgnoresProvenLeftovers(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1},
		{path: "b", index: 2},
	}
	proven := newAtomicPathSet()
	s, err := newSchedulerWithProof(tasks, 1, proven)
	if err != nil {
		t.Fatal(err)
	}
	s.markPathProven("a")
	s.markPathProven("b")
	if !s.exhausted() {
		t.Fatal("scheduler is not exhausted although every path is proven")
	}
	if _, ok := s.next(); ok {
		t.Fatal("a fully proven schedule still handed out work")
	}
}

// stats must surface which paths were settled, so a run can explain why it sent
// fewer candidates than the selected range.
func TestStatsReportProvenPaths(t *testing.T) {
	tasks := []scheduledTask{{path: "a", index: 0}, {path: "b", index: 1}}
	proven := newAtomicPathSet()
	s, err := newSchedulerWithProof(tasks, 1, proven)
	if err != nil {
		t.Fatal(err)
	}
	s.markPathProven("a")
	stats := map[pathID]pathStats{}
	for _, st := range s.stats() {
		stats[st.ID] = st
	}
	if !stats["a"].Proven {
		t.Error("proven path not reported as proven")
	}
	if stats["b"].Proven {
		t.Error("unproven path reported as proven")
	}
}

// A scheduler without a proof set must behave exactly as before, which is what the
// exhaustive baseline relies on.
func TestSchedulerWithoutProofDispatchesEverything(t *testing.T) {
	tasks := []scheduledTask{
		{path: "a", index: 0}, {path: "a", index: 1}, {path: "b", index: 2},
	}
	s, err := newScheduler(tasks, 1)
	if err != nil {
		t.Fatal(err)
	}
	if s.settled("a") {
		t.Fatal("a scheduler without a proof set reported a settled path")
	}
	if skipped := s.skippedByProof(); skipped != 0 {
		t.Fatalf("a scheduler without a proof set skipped %d candidates", skipped)
	}
	count := 0
	for {
		task, ok := s.next()
		if !ok {
			break
		}
		count++
		s.done(task.path)
	}
	if count != 3 {
		t.Fatalf("expected all 3 tasks, got %d", count)
	}
}

// The dispatcher must terminate once a proof settles the only path with remaining
// work, rather than blocking for candidates it will never send.
func TestDispatcherTerminatesAfterProof(t *testing.T) {
	const n = 6
	paths := make([]scheduledTask, 0, n)
	for i := 0; i < n; i++ {
		paths = append(paths, scheduledTask{path: "a", index: i})
	}
	proven := newAtomicPathSet()
	s, err := newSchedulerWithProof(paths, 1, proven)
	if err != nil {
		t.Fatal(err)
	}
	// Settle the only path before dispatch starts.
	s.markPathProven("a")

	in := make(chan dispatchItem[int])
	out := make(chan dispatchItem[int])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		defer close(in)
		for i := 0; i < n; i++ {
			in <- dispatchItem[int]{item: i, path: "a", done: make(chan struct{})}
		}
	}()

	done := startPathDispatcher(ctx, in, out, s)
	delivered := 0
	for range out {
		delivered++
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("dispatcher did not terminate although the only path was proven")
	}
	if delivered != 0 {
		t.Fatalf("dispatcher sent %d candidates for a proven path", delivered)
	}
}
