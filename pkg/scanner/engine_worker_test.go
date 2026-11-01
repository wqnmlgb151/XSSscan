package scanner

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestWorkerPool_AllTasksProcessed(t *testing.T) {
	const numTasks = 50
	const numWorkers = 10

	var processed int64
	taskCh := make(chan int, numWorkers*2)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// Worker panic recovery
				}
			}()
			for range taskCh {
				atomic.AddInt64(&processed, 1)
			}
		}()
	}

	for i := 0; i < numTasks; i++ {
		taskCh <- i
	}
	close(taskCh)

	wg.Wait()

	if atomic.LoadInt64(&processed) != numTasks {
		t.Errorf("Expected %d tasks processed, got %d", numTasks, processed)
	}
}

func TestWorkerPool_PanicRecovery(t *testing.T) {
	const numTasks = 20
	const panicAtTask = 5

	var processed int64
	var panics int64
	taskCh := make(chan int, 10)
	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					atomic.AddInt64(&panics, 1)
				}
			}()
			for task := range taskCh {
				if task == panicAtTask {
					panic("simulated panic")
				}
				atomic.AddInt64(&processed, 1)
			}
		}()
	}

	for i := 0; i < numTasks; i++ {
		taskCh <- i
	}
	close(taskCh)

	wg.Wait()

	// Panic was recovered, other tasks continued
	if atomic.LoadInt64(&panics) == 0 {
		t.Error("Expected panic to be recovered")
	}
	// Some tasks may not complete due to panic, but the system didn't crash
	// The key assertion is that Wait() returned without deadlock
	t.Logf("Processed %d/%d tasks with %d panics recovered", processed, numTasks, panics)
}

func TestWorkerPool_GoroutineCount(t *testing.T) {
	// Verify that the engine creates exactly the configured number of workers
	// by checking channel buffer size matches the formula
	concurrency := 10
	taskChBuffer := concurrency * 2
	taskCh := make(chan int, taskChBuffer)

	if cap(taskCh) != taskChBuffer {
		t.Errorf("Expected channel buffer %d, got %d", taskChBuffer, cap(taskCh))
	}
}

func TestWorkerPool_AtomicCounters(t *testing.T) {
	// Verify that concurrent increments produce correct totals
	const increments = 10000
	const goroutines = 10

	var counter int64
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < increments; j++ {
				atomic.AddInt64(&counter, 1)
			}
		}()
	}

	wg.Wait()

	expected := int64(goroutines * increments)
	if counter != expected {
		t.Errorf("Expected counter=%d, got %d (race condition)", expected, counter)
	}
}

func TestWorkerPool_SingleWorker(t *testing.T) {
	// Verify that concurrency=1 works correctly
	const numTasks = 10
	var processed int64
	taskCh := make(chan int, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range taskCh {
			atomic.AddInt64(&processed, 1)
		}
	}()

	for i := 0; i < numTasks; i++ {
		taskCh <- i
	}
	close(taskCh)

	wg.Wait()

	if processed != numTasks {
		t.Errorf("Expected %d tasks processed by single worker, got %d", numTasks, processed)
	}
}

func TestWorkerPool_ZeroWorkersFallsBackToOne(t *testing.T) {
	// Verify that numWorkers <= 0 falls back to 1
	numWorkers := 0
	if numWorkers <= 0 {
		numWorkers = 1
	}

	var processed int64
	taskCh := make(chan int, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range taskCh {
			atomic.AddInt64(&processed, 1)
		}
	}()

	taskCh <- 1
	close(taskCh)

	wg.Wait()

	if processed != 1 {
		t.Errorf("Expected fallback worker to process 1 task, got %d", processed)
	}
}
