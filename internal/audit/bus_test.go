package audit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingWriter struct{}

func (blockingWriter) Write(ctx context.Context, events []AuditEvent) error {
	<-ctx.Done()
	return ctx.Err()
}

type collectingWriter struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (w *collectingWriter) Write(_ context.Context, events []AuditEvent) error {
	w.mu.Lock()
	w.events = append(w.events, events...)
	w.mu.Unlock()
	return nil
}

func (w *collectingWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.events)
}

// failingWriter always returns an error.
type failingWriter struct{}

func (failingWriter) Write(_ context.Context, _ []AuditEvent) error {
	return fmt.Errorf("simulated write failure")
}

func TestAuditBusFlush_UsesWriterTimeout(t *testing.T) {
	t.Parallel()

	b := NewAuditBus(blockingWriter{})
	b.writerTimeout = 20 * time.Millisecond

	start := time.Now()
	b.flush([]AuditEvent{NewEvent(EventLogin, "tenant-a")})
	elapsed := time.Since(start)

	if elapsed > 250*time.Millisecond {
		t.Fatalf("flush took too long, expected timeout bounded execution: %v", elapsed)
	}
}

func TestAuditBusStop_FlushesBufferedEvents(t *testing.T) {
	t.Parallel()

	writer := &collectingWriter{}
	b := NewAuditBus(writer)
	b.flushInterval = time.Hour // avoid ticker flush interference
	b.batchSize = 1000

	b.Start()
	for i := 0; i < 25; i++ {
		b.Emit(NewEvent(EventLogin, "tenant-a"))
	}
	b.Stop()

	if got := writer.count(); got != 25 {
		t.Fatalf("expected 25 flushed events on stop, got %d", got)
	}
}

func TestAuditBusOverflow_UsesOverflowWriter(t *testing.T) {
	t.Parallel()

	// Tiny primary buffer to force overflow path quickly.
	primary := &collectingWriter{}
	b := &AuditBus{
		ch:                    make(chan AuditEvent, 1),
		writers:               []Writer{primary},
		batchSize:             100,
		flushInterval:         time.Hour,
		writerTimeout:         50 * time.Millisecond,
		overflowFlushInterval: 10 * time.Millisecond,
	}

	overflow := &collectingWriter{}
	b.SetOverflowWriter(overflow)

	// Do not start yet: we want deterministic channel saturation.
	b.Emit(NewEvent(EventLogin, "tenant-a")) // primary buffer
	b.Emit(NewEvent(EventLogin, "tenant-b")) // overflow queue
	b.Emit(NewEvent(EventLogin, "tenant-c")) // overflow queue

	if got := len(b.overflowCh); got != 2 {
		t.Fatalf("expected 2 queued overflow events, got %d", got)
	}

	b.Start()
	b.Stop()

	if got := overflow.count(); got != 2 {
		t.Fatalf("expected 2 events written to overflow, got %d", got)
	}
	if got := b.DroppedEvents.Load(); got != 0 {
		t.Fatalf("expected 0 dropped events (overflow handled them), got %d", got)
	}
}

func TestAuditBusOverflow_NoOverflowWriter_IncrementsDrop(t *testing.T) {
	t.Parallel()

	// Bus with tiny buffer, no overflow writer configured.
	b := &AuditBus{
		ch:            make(chan AuditEvent, 1),
		writers:       []Writer{&collectingWriter{}},
		batchSize:     100,
		flushInterval: time.Hour,
		writerTimeout: 50 * time.Millisecond,
	}

	b.Emit(NewEvent(EventLogin, "tenant-a")) // goes into buffer
	b.Emit(NewEvent(EventLogin, "tenant-b")) // buffer full, no overflow -> dropped

	if got := b.DroppedEvents.Load(); got != 1 {
		t.Fatalf("expected 1 dropped event, got %d", got)
	}
}

func TestAuditBusOverflow_FailingOverflow_IncrementsDrop(t *testing.T) {
	t.Parallel()

	b := &AuditBus{
		ch:                    make(chan AuditEvent, 1),
		writers:               []Writer{&collectingWriter{}},
		batchSize:             100,
		flushInterval:         time.Hour,
		writerTimeout:         50 * time.Millisecond,
		overflowFlushInterval: 10 * time.Millisecond,
	}
	b.SetOverflowWriter(&failingWriter{})

	b.Emit(NewEvent(EventLogin, "tenant-a")) // primary buffer
	b.Emit(NewEvent(EventLogin, "tenant-b")) // queued to overflow

	b.Start()
	b.Stop()

	if got := b.DroppedEvents.Load(); got != 1 {
		t.Fatalf("expected 1 dropped event (overflow failed), got %d", got)
	}
}

func TestAuditBusEmit_OverflowPathIsNonBlocking(t *testing.T) {
	t.Parallel()

	b := &AuditBus{
		ch:                    make(chan AuditEvent, 1),
		writers:               []Writer{&collectingWriter{}},
		batchSize:             100,
		flushInterval:         time.Hour,
		writerTimeout:         50 * time.Millisecond,
		overflowFlushInterval: 10 * time.Millisecond,
	}
	b.SetOverflowWriter(blockingWriter{})

	b.Emit(NewEvent(EventLogin, "tenant-a")) // fills primary channel

	start := time.Now()
	b.Emit(NewEvent(EventLogin, "tenant-b"))
	elapsed := time.Since(start)

	if elapsed > 20*time.Millisecond {
		t.Fatalf("expected non-blocking overflow enqueue, emit took %v", elapsed)
	}
}

func TestAuditBusStop_ConcurrentEmit_NoPanic(t *testing.T) {
	t.Parallel()

	writer := &collectingWriter{}
	b := NewAuditBus(writer)
	b.flushInterval = 5 * time.Millisecond
	b.batchSize = 10
	b.Start()

	var wg sync.WaitGroup
	var panics atomic.Int32
	start := make(chan struct{})

	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			<-start
			for i := 0; i < 400; i++ {
				func() {
					defer func() {
						if recover() != nil {
							panics.Add(1)
						}
					}()
					b.Emit(NewEvent(EventLogin, "tenant-a"))
				}()
			}
		}(g)
	}

	close(start)
	time.Sleep(2 * time.Millisecond)
	b.Stop()
	b.Stop() // idempotent
	wg.Wait()

	if got := panics.Load(); got != 0 {
		t.Fatalf("expected no panic in concurrent Emit/Stop, got %d panic(s)", got)
	}
}
