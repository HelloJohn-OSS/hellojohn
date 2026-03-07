package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// ConnectionPool administra conexiones de adapters por tenant.
// Thread-safe, usa singleflight para evitar creaciones duplicadas.
type ConnectionPool struct {
	// connections mapa de slug → AdapterConnection activa
	connections sync.Map

	// sf evita crear múltiples conexiones para el mismo tenant en paralelo
	sf singleflight.Group

	// factory crea nuevas conexiones
	factory ConnectionFactory

	// defaultCfg configuración default para nuevas conexiones
	defaultCfg PoolConfig
}

// ConnectionFactory función que crea una conexión para un tenant.
type ConnectionFactory func(ctx context.Context, tenantSlug string, cfg AdapterConfig) (AdapterConnection, error)

// PoolConfig configuración del pool.
type PoolConfig struct {
	// MaxIdleTime tiempo máximo de inactividad antes de cerrar conexión
	MaxIdleTime time.Duration

	// HealthCheckInterval intervalo para verificar conexiones activas
	HealthCheckInterval time.Duration

	// OnConnect callback cuando se crea una conexión nueva
	OnConnect func(slug string, conn AdapterConnection)

	// OnDisconnect callback cuando se cierra una conexión
	OnDisconnect func(slug string)
}

// poolEntry entrada en el pool con metadata.
type poolEntry struct {
	conn       AdapterConnection
	createdAt  time.Time
	lastUsedAt time.Time
	mu         sync.Mutex
}

func (e *poolEntry) touch() {
	e.mu.Lock()
	e.lastUsedAt = time.Now()
	e.mu.Unlock()
}

// NewConnectionPool crea un nuevo pool.
func NewConnectionPool(factory ConnectionFactory, cfg PoolConfig) *ConnectionPool {
	pool := &ConnectionPool{
		factory:    factory,
		defaultCfg: cfg,
	}

	// Iniciar health check si está configurado
	if cfg.HealthCheckInterval > 0 {
		go pool.healthCheckLoop(cfg.HealthCheckInterval)
	}

	return pool
}

// Get obtiene una conexión existente o crea una nueva.
func (p *ConnectionPool) Get(ctx context.Context, tenantSlug string, adapterCfg AdapterConfig) (AdapterConnection, error) {
	// Verificar si ya existe
	if val, ok := p.connections.Load(tenantSlug); ok {
		entry := val.(*poolEntry)
		entry.touch()
		return entry.conn, nil
	}

	// Usar singleflight para evitar creaciones paralelas
	result, err, _ := p.sf.Do(tenantSlug, func() (interface{}, error) {
		// Double-check después de obtener el lock
		if val, ok := p.connections.Load(tenantSlug); ok {
			return val.(*poolEntry).conn, nil
		}

		// Crear nueva conexión
		conn, err := p.factory(ctx, tenantSlug, adapterCfg)
		if err != nil {
			return nil, err
		}

		// Guardar en pool
		entry := &poolEntry{
			conn:       conn,
			createdAt:  time.Now(),
			lastUsedAt: time.Now(),
		}
		p.connections.Store(tenantSlug, entry)

		// Callback
		if p.defaultCfg.OnConnect != nil {
			p.defaultCfg.OnConnect(tenantSlug, conn)
		}

		return conn, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(AdapterConnection), nil
}

// Has verifica si existe una conexión para el tenant.
func (p *ConnectionPool) Has(tenantSlug string) bool {
	_, ok := p.connections.Load(tenantSlug)
	return ok
}

// Close cierra la conexión de un tenant específico.
func (p *ConnectionPool) Close(tenantSlug string) error {
	val, ok := p.connections.LoadAndDelete(tenantSlug)
	if !ok {
		return nil
	}

	entry := val.(*poolEntry)
	if p.defaultCfg.OnDisconnect != nil {
		p.defaultCfg.OnDisconnect(tenantSlug)
	}

	return entry.conn.Close()
}

// CloseAll cierra todas las conexiones.
func (p *ConnectionPool) CloseAll() error {
	var errs []error

	p.connections.Range(func(key, value interface{}) bool {
		slug := key.(string)
		entry := value.(*poolEntry)

		if p.defaultCfg.OnDisconnect != nil {
			p.defaultCfg.OnDisconnect(slug)
		}

		if err := entry.conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", slug, err))
		}

		p.connections.Delete(key)
		return true
	})

	if len(errs) > 0 {
		return fmt.Errorf("errors closing connections: %v", errs)
	}
	return nil
}

// Stats retorna estadísticas del pool.
func (p *ConnectionPool) Stats() PoolStats {
	stats := PoolStats{
		Connections: make(map[string]ConnectionStats),
	}

	p.connections.Range(func(key, value interface{}) bool {
		slug := key.(string)
		entry := value.(*poolEntry)

		entry.mu.Lock()
		stats.Connections[slug] = ConnectionStats{
			Driver:     entry.conn.Name(),
			CreatedAt:  entry.createdAt,
			LastUsedAt: entry.lastUsedAt,
		}
		entry.mu.Unlock()

		stats.TotalActive++
		return true
	})

	return stats
}

// PoolStats estadísticas del pool.
type PoolStats struct {
	TotalActive int
	Connections map[string]ConnectionStats
}

// ConnectionStats estadísticas de una conexión.
type ConnectionStats struct {
	Driver     string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// healthCheckLoop verifica conexiones periódicamente.
func (p *ConnectionPool) healthCheckLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		p.runHealthCheck()
	}
}

func (p *ConnectionPool) runHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var toClose []string

	p.connections.Range(func(key, value interface{}) bool {
		slug := key.(string)
		entry := value.(*poolEntry)

		// Verificar si la conexión responde
		if err := entry.conn.Ping(ctx); err != nil {
			toClose = append(toClose, slug)
		}

		// Verificar idle time
		entry.mu.Lock()
		idle := time.Since(entry.lastUsedAt)
		entry.mu.Unlock()

		if p.defaultCfg.MaxIdleTime > 0 && idle > p.defaultCfg.MaxIdleTime {
			toClose = append(toClose, slug)
		}

		return true
	})

	// Cerrar conexiones inactivas o fallidas
	for _, slug := range toClose {
		p.Close(slug)
	}
}

// Refresh cierra y recrea la conexión de un tenant.
func (p *ConnectionPool) Refresh(ctx context.Context, tenantSlug string, adapterCfg AdapterConfig) (AdapterConnection, error) {
	// Cerrar existente
	p.Close(tenantSlug)

	// Crear nueva
	return p.Get(ctx, tenantSlug, adapterCfg)
}
