package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// counters agrupa los contadores en memoria para un tenant/mes.
type counters struct {
	mu            sync.Mutex
	logins        int
	registrations int
	tokens        int
	apiCalls      int
	// mauUsers: set de userIDs únicos vistos este mes (para flush inicial)
	mauUsers map[string]struct{}
}

// UsageCollector escucha eventos de auditoría y persiste métricas de uso.
// Implementa audit.Writer para integrarse con AuditBus.
type UsageCollector struct {
	repo          repository.UsageRepository
	mu            sync.RWMutex
	buffers       map[string]*counters // key: "tenantID:YYYY-MM"
	flushInterval time.Duration
	done          chan struct{}
	wg            sync.WaitGroup
}

// compile-time check: UsageCollector implementa audit.Writer
var _ audit.Writer = (*UsageCollector)(nil)

// NewUsageCollector crea un UsageCollector con flush cada 5 minutos.
func NewUsageCollector(repo repository.UsageRepository) *UsageCollector {
	return &UsageCollector{
		repo:          repo,
		buffers:       make(map[string]*counters),
		flushInterval: 5 * time.Minute,
		done:          make(chan struct{}),
	}
}

// Write implementa audit.Writer. Recibe eventos en batch desde el AuditBus.
// Non-blocking: solo actualiza contadores en memoria.
func (c *UsageCollector) Write(_ context.Context, events []audit.AuditEvent) error {
	now := time.Now()
	for _, ev := range events {
		if ev.TenantID == "" {
			continue
		}
		c.processEvent(ev, now)
	}
	return nil
}

func (c *UsageCollector) processEvent(ev audit.AuditEvent, now time.Time) {
	monthKey := usageMonthKey(now)
	key := ev.TenantID + ":" + monthKey

	c.mu.Lock()
	buf, ok := c.buffers[key]
	if !ok {
		buf = &counters{mauUsers: make(map[string]struct{})}
		c.buffers[key] = buf
	}
	c.mu.Unlock()

	buf.mu.Lock()
	defer buf.mu.Unlock()

	buf.apiCalls++

	switch ev.Type {
	case audit.EventLogin:
		if ev.Result == audit.ResultSuccess && ev.ActorID != "" {
			buf.logins++
			buf.mauUsers[ev.ActorID] = struct{}{}
		}
	case audit.EventRegister:
		if ev.Result == audit.ResultSuccess {
			buf.registrations++
		}
	case audit.EventTokenIssued:
		if ev.Result == audit.ResultSuccess {
			buf.tokens++
		}
	}
}

// Start inicia el goroutine de flush periódico. Debe llamarse una vez.
func (c *UsageCollector) Start() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(c.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.Flush(context.Background())
			case <-c.done:
				c.Flush(context.Background())
				return
			}
		}
	}()
}

// Stop señala al goroutine que haga el último flush y termine.
// Bloquea hasta que el flush esté completo.
func (c *UsageCollector) Stop() {
	close(c.done)
	c.wg.Wait()
}

// Flush persiste todos los contadores en memoria a la DB.
func (c *UsageCollector) Flush(ctx context.Context) {
	c.mu.Lock()
	snapshot := c.buffers
	c.buffers = make(map[string]*counters)
	c.mu.Unlock()

	for key, buf := range snapshot {
		tenantID, month := parseUsageKey(key)
		if tenantID == "" {
			continue
		}

		buf.mu.Lock()
		logins := buf.logins
		regs := buf.registrations
		tokens := buf.tokens
		apiCalls := buf.apiCalls
		mauUsers := buf.mauUsers
		buf.mu.Unlock()

		// Persist MAU users (idempotente via IncrementMAU)
		for userID := range mauUsers {
			if err := c.repo.IncrementMAU(ctx, tenantID, userID, month); err != nil {
				logger.L().Error("usage_collector: IncrementMAU failed",
					logger.String("tenant", tenantID),
					logger.Err(err),
				)
			}
		}

		// Persist counters
		// total_logins para usuarios ya contados este mes (que no hicieron IncrementMAU)
		extraLogins := logins - len(mauUsers)

		fields := map[string]int{
			"total_registrations": regs,
			"total_tokens_issued": tokens,
			"total_api_calls":     apiCalls,
		}
		if extraLogins > 0 {
			fields["total_logins"] = extraLogins
		}

		for field, delta := range fields {
			if delta <= 0 {
				continue
			}
			if err := c.repo.IncrementCounter(ctx, tenantID, month, field, delta); err != nil {
				logger.L().Error("usage_collector: IncrementCounter failed",
					logger.String("tenant", tenantID),
					logger.String("field", field),
					logger.Err(err),
				)
			}
		}
	}
}

// usageMonthKey retorna el mes como string "YYYY-MM" para usar como clave de buffer.
func usageMonthKey(t time.Time) string {
	return t.UTC().Format("2006-01")
}

// parseUsageKey extrae tenantID y month de una clave "tenantID:YYYY-MM".
func parseUsageKey(key string) (tenantID string, month time.Time) {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == ':' {
			tenantID = key[:i]
			month, _ = time.Parse("2006-01", key[i+1:])
			return
		}
	}
	return "", time.Time{}
}
