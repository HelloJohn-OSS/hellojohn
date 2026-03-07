package audit

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// AuditBus is a non-blocking, async event bus that collects audit events
// and flushes them in batches to registered Writers.
type AuditBus struct {
	ch            chan AuditEvent
	writers       []Writer
	batchSize     int
	flushInterval time.Duration
	writerTimeout time.Duration
	wg            sync.WaitGroup
	stopped       atomic.Bool // fast-path reject for Emit after Stop
	started       atomic.Bool
	stopOnce      sync.Once
	emitMu        sync.RWMutex // synchronizes Emit sends with Stop() channel close

	// overflow is an optional durable writer used as fallback when the
	// channel buffer is full.
	overflow Writer
	// overflowCh decouples overflow persistence from request goroutines.
	overflowCh chan AuditEvent
	// overflowFlushInterval controls batch flush cadence for overflow events.
	overflowFlushInterval time.Duration

	// DroppedEvents counts events that could not be enqueued AND could not
	// be persisted by fallback paths. Exposed for monitoring/alerting.
	DroppedEvents atomic.Uint64
}

// NewAuditBus creates a new bus with the given writers.
// The bus must be started with Start() and stopped with Stop().
func NewAuditBus(writers ...Writer) *AuditBus {
	return &AuditBus{
		ch:                    make(chan AuditEvent, 5000),
		writers:               writers,
		batchSize:             100,
		flushInterval:         3 * time.Second,
		writerTimeout:         5 * time.Second,
		overflowFlushInterval: 250 * time.Millisecond,
	}
}

// SetOverflowWriter configures a durable fallback writer used when the
// channel buffer is full so overflow events are persisted durably instead
// of being silently dropped.
func (b *AuditBus) SetOverflowWriter(w Writer) {
	b.emitMu.Lock()
	defer b.emitMu.Unlock()

	b.overflow = w
	if w != nil && b.overflowCh == nil {
		size := cap(b.ch)
		if size < 1024 {
			size = 1024
		}
		b.overflowCh = make(chan AuditEvent, size)
	}
}

// Emit publishes an event to the bus. It is non-blocking: if the channel
// buffer is full or the bus has been stopped, the event is dropped after
// best-effort enqueue to the overflow queue.
// Safe to call concurrently, even during or after Stop().
func (b *AuditBus) Emit(event AuditEvent) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}

	// Hold read-lock while sending so Stop() cannot close channels concurrently.
	b.emitMu.RLock()
	if b.stopped.Load() {
		b.emitMu.RUnlock()
		return
	}

	select {
	case b.ch <- event:
	default:
		// Buffer full: enqueue to overflow queue without blocking request path.
		if b.overflow != nil && b.overflowCh != nil {
			select {
			case b.overflowCh <- event:
				log.Printf("WARN: audit bus buffer full, queued overflow event %s for tenant %s", event.Type, event.TenantID)
			default:
				b.DroppedEvents.Add(1)
				log.Printf("WARN: audit bus buffer full and overflow queue full, dropping event %s for tenant %s", event.Type, event.TenantID)
			}
		} else if b.overflow != nil {
			// Defensive branch for misconfigured startup order.
			b.DroppedEvents.Add(1)
			log.Printf("WARN: audit bus buffer full but overflow queue unavailable, dropping event %s for tenant %s", event.Type, event.TenantID)
		} else {
			b.DroppedEvents.Add(1)
			log.Printf("WARN: audit bus buffer full, dropping event %s for tenant %s", event.Type, event.TenantID)
		}
	}
	b.emitMu.RUnlock()
}

// Start begins the background goroutines that consume events and flush
// them in batches to writers.
func (b *AuditBus) Start() {
	if !b.started.CompareAndSwap(false, true) {
		return
	}

	if b.overflow != nil && b.overflowCh != nil {
		b.wg.Add(1)
		go b.runOverflowWorker()
	}

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		buffer := make([]AuditEvent, 0, b.batchSize)
		ticker := time.NewTicker(b.flushInterval)
		defer ticker.Stop()

		for {
			select {
			case event, ok := <-b.ch:
				if !ok {
					if len(buffer) > 0 {
						b.flush(buffer)
					}
					return
				}
				buffer = append(buffer, event)
				if len(buffer) >= b.batchSize {
					b.flush(buffer)
					buffer = make([]AuditEvent, 0, b.batchSize)
				}
			case <-ticker.C:
				if len(buffer) > 0 {
					b.flush(buffer)
					buffer = make([]AuditEvent, 0, b.batchSize)
				}
			}
		}
	}()
}

// Stop signals workers to finish and waits for final flush.
// Safe to call multiple times.
func (b *AuditBus) Stop() {
	b.stopOnce.Do(func() {
		// Block new Emit() sends and close channels exactly once.
		b.emitMu.Lock()
		b.stopped.Store(true)
		close(b.ch)
		if b.overflowCh != nil {
			close(b.overflowCh)
		}
		b.emitMu.Unlock()

		b.wg.Wait()
	})
}

// flush writes a batch of events to every registered writer.
// Errors are logged but do not stop other writers.
func (b *AuditBus) flush(events []AuditEvent) {
	for _, w := range b.writers {
		ctx, cancel := context.WithTimeout(context.Background(), b.writerTimeout)
		err := w.Write(ctx, events)
		cancel()
		if err != nil {
			log.Printf("WARN: audit writer %T failed: %v", w, err)
		}
	}
}

// runOverflowWorker persists overflow events in the background using bounded
// batches so Emit remains non-blocking even when the main buffer is saturated.
func (b *AuditBus) runOverflowWorker() {
	defer b.wg.Done()
	if b.overflow == nil || b.overflowCh == nil {
		return
	}

	buffer := make([]AuditEvent, 0, b.batchSize)
	flush := func() {
		if len(buffer) == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), b.writerTimeout)
		err := b.overflow.Write(ctx, buffer)
		cancel()
		if err != nil {
			b.DroppedEvents.Add(uint64(len(buffer)))
			log.Printf("WARN: audit overflow writer %T failed: %v (dropping %d event(s))", b.overflow, err, len(buffer))
		}
		buffer = buffer[:0]
	}

	ticker := time.NewTicker(b.overflowFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-b.overflowCh:
			if !ok {
				flush()
				return
			}
			buffer = append(buffer, event)
			if len(buffer) >= b.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
