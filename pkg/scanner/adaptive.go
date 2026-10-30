package scanner

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"sync"

	xctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
)

/*
Path-scoped candidate scheduling for the adaptive strategy.

ENGINEERING_PLAN.md §25.9 requires that a first version schedule on independent
paths with these properties:

  - at most one in-flight decision task per path, so a path cannot have a large
    batch of equivalent candidates in flight before any feedback arrives;
  - independent paths rotate, so one cheap candidate family cannot consume the
    whole budget (§25.6: "保留每个独立上下文/候选族的公平探索");
  - work for another path is never suppressed by progress on this one (§25.9:
    "证明成功后停止未派发的等价任务"; the plan is explicit that a success on one
    parameter does not cover another);
  - a bounded, deterministic order so a run is reproducible and diffable.

The scheduler only consumes path-scoped execution proofs. The engine holds each
path slot through its browser decision, publishes proof before releasing the slot,
and retains negative or incomplete evidence for reporting. Adaptive is the default;
explicit exhaustive preserves full-range dispatch.
*/

// scheduler is a pure decision component: it owns per-path progress and hands out
// the next task to send. It performs no I/O, so a caller can drive it from a single
// dispatch goroutine and test it without any server.
//
// It is driven by one goroutine only and therefore holds no lock of its own. State
// that another goroutine must change — currently the set of proven paths — arrives
// through an atomic provider instead of a lock, so the dispatcher needs no mutex on
// its hot path.
type scheduler struct {
	// order is every dispatchable path, in first-seen order. Stable order makes
	// a scan reproducible when concurrency is fixed.
	order []pathID
	// pending holds the not-yet-dispatched task indices for each path, in the
	// order the generator produced them.
	pending map[pathID][]int
	// inflight counts tasks dispatched but not yet completed, per path.
	inflight map[pathID]int
	// dispatched counts tasks handed out per path, for reporting.
	dispatched map[pathID]int
	// maxPerPath bounds concurrent tasks for one path. Zero or less disables the
	// bound, which reproduces the exhaustive ordering.
	maxPerPath int
	// cursor is the rotation position across order.
	cursor int
	// proven optionally reports paths that an execution proof has already settled.
	// A proven path stops being scheduled; see markPathProven.
	proven *atomicPathSet
}

// atomicPathSet is a concurrent set of proven paths. It exists so the browser
// verification side can record a proof while the dispatch goroutine keeps reading,
// without putting a mutex on the dispatch path.
type atomicPathSet struct {
	mu    sync.RWMutex
	paths map[pathID]struct{}
}

func newAtomicPathSet() *atomicPathSet {
	return &atomicPathSet{paths: make(map[pathID]struct{})}
}

func (s *atomicPathSet) add(id pathID) {
	if s == nil || id == "" {
		return
	}
	s.mu.Lock()
	s.paths[id] = struct{}{}
	s.mu.Unlock()
}

func (s *atomicPathSet) has(id pathID) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	_, ok := s.paths[id]
	s.mu.RUnlock()
	return ok
}

func (s *atomicPathSet) len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	n := len(s.paths)
	s.mu.RUnlock()
	return n
}

// settled reports whether this path has been proven, and therefore whether its
// remaining candidates may be skipped.
func (s *scheduler) settled(id pathID) bool { return s.proven.has(id) }

// newScheduler builds a scheduler over tasks already attributed to paths.
//
// Every task must carry a non-empty path: an unattributed task cannot be placed
// on the rotation, and silently dropping it would lose coverage. Callers that
// cannot attribute a task must fall back to the input-scoped path from
// primaryPathID rather than passing an empty id.
func newScheduler(tasks []scheduledTask, maxPerPath int) (*scheduler, error) {
	return newSchedulerWithProof(tasks, maxPerPath, nil)
}

func newSchedulerWithProof(tasks []scheduledTask, maxPerPath int, proven *atomicPathSet) (*scheduler, error) {
	s := &scheduler{
		pending:    make(map[pathID][]int),
		inflight:   make(map[pathID]int),
		dispatched: make(map[pathID]int),
		maxPerPath: maxPerPath,
		proven:     proven,
	}
	for i, t := range tasks {
		if t.path == "" {
			return nil, fmt.Errorf("task %d has no path identity", i)
		}
		if _, seen := s.pending[t.path]; !seen {
			s.order = append(s.order, t.path)
		}
		s.pending[t.path] = append(s.pending[t.path], i)
	}
	return s, nil
}

// markPathProven records that a browser execution proof settled this path, so its
// remaining candidates are no longer dispatched.
//
// The proof must be scoped to exactly this path. A proof for one reflection
// position says nothing about another position of the same parameter, nor about the
// same parameter under a different original query value, which is why the path id
// carries the request identity as well as the reflection anchor.
func (s *scheduler) markPathProven(id pathID) { s.proven.add(id) }

// scheduledTask pairs a dispatchable item with the path it belongs to.
type scheduledTask struct {
	path  pathID
	index int // caller-supplied handle, e.g. an index into the task list
	// Only one anchored reflection and a matching context can license early
	// convergence. Browser dialogs alone do not identify a reflection position.
	canConverge bool
}

// next returns the next task to dispatch and whether one was available.
//
// Selection walks the path rotation from the cursor and picks the first path
// that has both remaining work and capacity. Walking from a cursor rather than
// always starting at order[0] is what gives independent paths fair service: a
// path with many candidates cannot starve a path that has few.
func (s *scheduler) next() (scheduledTask, bool) { return s.nextBounded(-1) }

// nextBounded is next() restricted to task indices below limit, or unrestricted
// when limit is negative.
//
// The restriction exists because a caller may stream items in rather than holding
// the whole slice up front. A task whose index has not arrived yet is SKIPPED, not
// consumed, so it stays eligible once its item lands. Skipping the whole path
// rather than reordering it keeps per-path candidate order intact.
func (s *scheduler) nextBounded(limit int) (scheduledTask, bool) {
	if len(s.order) == 0 {
		return scheduledTask{}, false
	}
	for i := 0; i < len(s.order); i++ {
		pos := (s.cursor + i) % len(s.order)
		id := s.order[pos]
		if s.settled(id) {
			// An execution proof settled this path; its remaining candidates are
			// equivalent work that no longer needs sending.
			continue
		}
		queue := s.pending[id]
		if len(queue) == 0 {
			continue
		}
		if s.maxPerPath > 0 && s.inflight[id] >= s.maxPerPath {
			continue
		}
		if limit >= 0 && queue[0] >= limit {
			continue
		}
		index := queue[0]
		s.pending[id] = queue[1:]
		s.inflight[id]++
		s.dispatched[id]++
		// Resume the rotation just past the path that was served, so the next
		// call prefers a different path.
		s.cursor = (pos + 1) % len(s.order)
		return scheduledTask{path: id, index: index}, true
	}
	return scheduledTask{}, false
}

// inFlightTotal reports how many dispatched tasks have not been released yet.
func (s *scheduler) inFlightTotal() int {
	total := 0
	for _, n := range s.inflight {
		total += n
	}
	return total
}

// done records that a dispatched task for this path has finished, freeing its
// in-flight slot. It is a no-op for a path the scheduler does not know, so a late
// result from a previous run cannot corrupt current state.
func (s *scheduler) done(id pathID) {
	if _, known := s.inflight[id]; !known {
		return
	}
	if s.inflight[id] > 0 {
		s.inflight[id]--
	}
}

// remaining reports how many tasks have not been dispatched for a path.
func (s *scheduler) remaining(id pathID) int { return len(s.pending[id]) }

// exhausted reports whether every task is finished: dispatched, or dropped because
// a proof settled its path. A proven path's leftover candidates count as finished —
// otherwise the dispatcher would wait forever for work it is right not to send.
func (s *scheduler) exhausted() bool {
	for id, queue := range s.pending {
		if len(queue) > 0 && !s.settled(id) {
			return false
		}
	}
	return true
}

// skippedByProof counts candidates a settled path never had to send.
func (s *scheduler) skippedByProof() int {
	total := 0
	for id, queue := range s.pending {
		if s.settled(id) {
			total += len(queue)
		}
	}
	return total
}

// pathStats summarises one path for reporting. Counts only; no verdict is
// implied by any field.
type pathStats struct {
	ID         pathID
	Dispatched int
	Remaining  int
	// Proven reports that an execution proof settled this path, which is a
	// statement about the evidence obtained, not about the target being safe.
	Proven bool
}

// stats returns a deterministic, order-stable summary of every path.
func (s *scheduler) stats() []pathStats {
	out := make([]pathStats, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, pathStats{
			ID:         id,
			Dispatched: s.dispatched[id],
			Remaining:  len(s.pending[id]),
			Proven:     s.settled(id),
		})
	}
	return out
}

// buildScheduledTasks attributes each payload of one injection point to a path.
//
// Attribution is deliberately conservative. A payload is only assigned to its own
// reflection position when the detector produced a usable anchor for it; the
// engine cannot yet tell which of several positions executed a payload. Wider
// fallback buckets remain dispatchable, but cannot license early convergence.
func buildScheduledTasks(target model.Target, injection model.InjectionPoint, payloads []payload.Payload) ([]scheduledTask, error) {
	input, inputID, positions := reflectionIdentitiesFor(target, injection)
	if input.Incomplete {
		// An incomplete identity must not be used to separate or merge paths.
		// Fall back to one path for every payload of this injection point.
		id := pathID(inputID)
		tasks := make([]scheduledTask, 0, len(payloads))
		for i := range payloads {
			tasks = append(tasks, scheduledTask{path: id, index: i})
		}
		return tasks, nil
	}

	// Map a payload's declared context type to the path of the reflection
	// position that produced it. Several positions may share a context type; the
	// first anchored one wins, which keeps the mapping deterministic instead of
	// depending on map iteration order.
	byContext := make(map[xctx.ContextType]pathID, len(positions))
	for i := range injection.Contexts {
		if i >= len(positions) || !positions[i].Anchored {
			continue
		}
		if _, exists := byContext[injection.Contexts[i].Type]; !exists {
			byContext[injection.Contexts[i].Type] = positions[i].id()
		}
	}
	fallback := primaryPathID(inputID, positions)

	tasks := make([]scheduledTask, 0, len(payloads))
	for i := range payloads {
		id := fallback
		canConverge := false
		if mapped, ok := byContext[payloads[i].Context]; ok {
			id = mapped
			canConverge = len(positions) == 1 && positions[0].Anchored
		}
		tasks = append(tasks, scheduledTask{path: id, index: i, canConverge: canConverge})
	}
	return tasks, nil
}

// sortPathStats orders stats by dispatched count then id, for stable output.
func sortPathStats(stats []pathStats) {
	sort.SliceStable(stats, func(i, j int) bool {
		if stats[i].Dispatched != stats[j].Dispatched {
			return stats[i].Dispatched > stats[j].Dispatched
		}
		return stats[i].ID < stats[j].ID
	})
}

// formatPathStats renders a bounded, human-readable coverage summary. It is
// intentionally counts-only: the plan forbids presenting path counts as a
// coverage percentage or as evidence that a target is safe.
func formatPathStats(stats []pathStats, limit int) string {
	sortPathStats(stats)
	if limit > 0 && len(stats) > limit {
		stats = stats[:limit]
	}
	out := make([]string, 0, len(stats))
	for _, s := range stats {
		out = append(out, string(s.ID)+" dispatched="+strconv.Itoa(s.Dispatched)+" remaining="+strconv.Itoa(s.Remaining))
	}
	return fmt.Sprintf("paths=%d %v", len(stats), out)
}

// scheduledTasksOf projects dispatchable items onto the scheduler's view of
// them. The caller keeps ownership of the item type; the scheduler only needs the
// path and the position of each item in that slice.
func scheduledTasksOf[T any](items []T, pathOf func(T) pathID) []scheduledTask {
	out := make([]scheduledTask, 0, len(items))
	for i, item := range items {
		out = append(out, scheduledTask{path: pathOf(item), index: i})
	}
	return out
}

// startPathDispatcher pumps `in` into `out` following the scheduler's order, and
// releases a path's in-flight slot whenever a worker reports that path as
// finished on `released`.
//
// It exists because the previous dispatch loop walked a prebuilt slice and pushed
// everything through a buffered channel, which let every candidate for one
// injection point be queued before any response came back. The plan requires the
// opposite: "每路径初始最多1个在途决策任务，防止反馈到来前已发送大量等价候选".
// Rotation across independent paths is what keeps that bound from starving a path
// generated last that has few candidates.
//
// Items are numbered by arrival order, which the caller must make match its
// scheduler's index order (send the slice in order). The dispatcher never asks the
// scheduler for an item it has not received: an earlier revision dispatched before
// the item arrived, then treated the resulting index mismatch as a stale entry and
// burned through the whole schedule without sending anything. Numbering here
// removes that failure mode by construction.
//
// dispatchItem is one unit the dispatcher may hand to a worker. done is closed by
// the consumer once the attempt has finished, which is how the dispatcher learns
// that this path's in-flight slot is free again.
type dispatchItem[T any] struct {
	item T
	path pathID
	done chan struct{}
}

// startPathDispatcher pumps `in` into `out` following the scheduler's order.
//
// It exists because the previous dispatch loop walked a prebuilt slice and pushed
// everything through a buffered channel, which let every candidate for one injection
// point be queued before any response came back. The plan requires the opposite:
// "每路径初始最多1个在途决策任务，防止反馈到来前已发送大量等价候选".
// Rotation across independent paths is what keeps that bound from starving a path
// generated last that has few candidates.
//
// Items are numbered by arrival order, which the caller must make match its
// scheduler's index order (send the slice in order). The dispatcher never asks the
// scheduler for an item it has not received: an earlier revision dispatched before
// the item arrived, then treated the resulting index mismatch as a stale entry and
// burned through the whole schedule without sending anything.
//
// A slot includes time in the worker queue, HTTP work and execution verification,
// and is released only when the item's done channel closes.
//
// Ordering and in-flight accounting are the only decisions made here. What to do with
// a result — including stopping a path early — stays with the caller, so this loop
// cannot silently suppress coverage on its own.
func startPathDispatcher[T any](ctx context.Context, in <-chan dispatchItem[T], out chan<- dispatchItem[T], s *scheduler) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		var relays sync.WaitGroup
		defer func() {
			relays.Wait()
			close(out)
			close(done)
		}()

		var pending []dispatchItem[T]
		input := in

		// release forwards a finished item's slot back to this goroutine. It is
		// buffered per dispatch, so a relay never blocks on a loop that has stopped.
		release := make(chan pathID, 64)

		for {
			// Accept every already-available item before choosing what to send.
		drain:
			for input != nil {
				select {
				case item, ok := <-input:
					if !ok {
						input = nil
						break
					}
					pending = append(pending, item)
				default:
					break drain
				}
			}

			sent := false
			for {
				select {
				case id := <-release:
					s.done(id)
					continue
				default:
				}
				// Only ask for work the local queue can satisfy: an index at or
				// beyond len(pending) belongs to an item that has not arrived.
				task, ok := s.nextBounded(len(pending))
				if !ok {
					break
				}
				entry := pending[task.index]
				select {
				case out <- entry:
					sent = true
					// The item is in flight now, so start watching for its release.
					relays.Add(1)
					go func(d chan struct{}, id pathID) {
						defer relays.Done()
						select {
						case <-d:
							select {
							case release <- id:
							case <-ctx.Done():
							}
						case <-ctx.Done():
						}
					}(entry.done, entry.path)
				case <-ctx.Done():
					return
				}
			}

			if sent {
				continue
			}
			if s.exhausted() && input == nil && s.inFlightTotal() == 0 {
				return
			}

			// Nothing dispatchable. Either work is in flight and will free a slot, or
			// more input is coming.
			select {
			case id := <-release:
				s.done(id)
			case item, ok := <-input:
				if !ok {
					input = nil
					continue
				}
				pending = append(pending, item)
			case <-ctx.Done():
				return
			}
		}
	}()
	return done
}
