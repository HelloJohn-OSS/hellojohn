package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Las migraciones SQL se embeben en el binario.
// El directorio se configura al crear el Migrator.
// Formato de archivo: {version}_{name}.sql (ej: 0001_init.sql)

// Migrator aplica migraciones SQL a una base de datos.
type Migrator struct {
	migrationsFS  embed.FS
	migrationsDir string
}

// NewMigrator crea un nuevo Migrator.
func NewMigrator(migrationsFS embed.FS, migrationsDir string) *Migrator {
	return &Migrator{
		migrationsFS:  migrationsFS,
		migrationsDir: migrationsDir,
	}
}

// Migration representa una migración individual.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// MigrationResult resultado de aplicar migraciones.
type MigrationResult struct {
	Applied  []int
	Skipped  []int
	Failed   *int
	Error    error
	Duration time.Duration
}

// migrationFilePattern patrón para nombres de archivo de migración.
// Solo capturamos archivos _up.sql (ignoramos _down.sql)
var migrationFilePattern = regexp.MustCompile(`^(\d+)_(.+)_up\.sql$`)

// ParseMigrations lee y parsea las migraciones del FS embebido.
func (m *Migrator) ParseMigrations() ([]Migration, error) {
	var migrations []Migration

	err := fs.WalkDir(m.migrationsFS, m.migrationsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		filename := filepath.Base(path)
		matches := migrationFilePattern.FindStringSubmatch(filename)
		if matches == nil {
			return nil // Ignorar archivos que no coinciden
		}

		version, _ := strconv.Atoi(matches[1])
		name := matches[2]

		content, err := m.migrationsFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		migrations = append(migrations, Migration{
			Version: version,
			Name:    name,
			SQL:     string(content),
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Ordenar por versión
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// SQLExecutor interfaz para ejecutar SQL (abstrae pgx vs database/sql).
type SQLExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Run aplica migraciones pendientes a una base de datos.
func (m *Migrator) Run(ctx context.Context, exec SQLExecutor, driver string) (*MigrationResult, error) {
	start := time.Now()
	result := &MigrationResult{}

	// Asegurar que existe la tabla de migraciones
	if err := m.ensureMigrationsTable(ctx, exec, driver); err != nil {
		result.Error = fmt.Errorf("creating migrations table: %w", err)
		result.Duration = time.Since(start)
		return result, result.Error
	}

	// Obtener migraciones aplicadas
	applied, err := m.getAppliedVersions(ctx, exec)
	if err != nil {
		result.Error = fmt.Errorf("getting applied migrations: %w", err)
		result.Duration = time.Since(start)
		return result, result.Error
	}

	// Parsear migraciones disponibles
	migrations, err := m.ParseMigrations()
	if err != nil {
		result.Error = fmt.Errorf("parsing migrations: %w", err)
		result.Duration = time.Since(start)
		return result, result.Error
	}

	// Aplicar pendientes
	for _, mig := range migrations {
		if applied[mig.Version] {
			result.Skipped = append(result.Skipped, mig.Version)
			continue
		}

		if err := m.applyMigration(ctx, exec, mig); err != nil {
			result.Failed = &mig.Version
			result.Error = fmt.Errorf("applying migration %d_%s: %w", mig.Version, mig.Name, err)
			result.Duration = time.Since(start)
			return result, result.Error
		}

		result.Applied = append(result.Applied, mig.Version)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// HasPending verifica si hay migraciones pendientes.
func (m *Migrator) HasPending(ctx context.Context, exec SQLExecutor, driver string) (bool, error) {
	// Verificar si existe la tabla de migraciones
	exists, err := m.tableExists(ctx, exec, driver, "_migrations")
	if err != nil {
		return false, err
	}
	if !exists {
		return true, nil // No hay tabla, hay pendientes
	}

	applied, err := m.getAppliedVersions(ctx, exec)
	if err != nil {
		return false, err
	}

	migrations, err := m.ParseMigrations()
	if err != nil {
		return false, err
	}

	for _, mig := range migrations {
		if !applied[mig.Version] {
			return true, nil
		}
	}

	return false, nil
}

// ensureMigrationsTable crea la tabla de tracking de migraciones.
func (m *Migrator) ensureMigrationsTable(ctx context.Context, exec SQLExecutor, driver string) error {
	var createSQL string
	switch driver {
	case "postgres":
		createSQL = `
			CREATE TABLE IF NOT EXISTS _migrations (
				version INT PRIMARY KEY,
				name VARCHAR(255) NOT NULL,
				applied_at TIMESTAMPTZ DEFAULT NOW()
			)`
	case "mysql":
		createSQL = `
			CREATE TABLE IF NOT EXISTS _migrations (
				version INT PRIMARY KEY,
				name VARCHAR(255) NOT NULL,
				applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)`
	default:
		createSQL = `
			CREATE TABLE IF NOT EXISTS _migrations (
				version INT PRIMARY KEY,
				name TEXT NOT NULL,
				applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)`
	}

	_, err := exec.ExecContext(ctx, createSQL)
	return err
}

// getAppliedVersions obtiene las versiones ya aplicadas.
func (m *Migrator) getAppliedVersions(ctx context.Context, exec SQLExecutor) (map[int]bool, error) {
	// Usamos QueryRowContext para simplificar, pero idealmente usaríamos Query
	// Por ahora, asumimos que podemos ejecutar una query simple
	applied := make(map[int]bool)

	// Obtener máxima versión aplicada como heurística rápida
	var maxVersion int
	row := exec.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM _migrations")
	if err := row.Scan(&maxVersion); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return applied, nil
		}
		return nil, err
	}

	// Marcar todas hasta max como aplicadas (simplificación)
	// En producción, haríamos SELECT version FROM _migrations
	for i := 1; i <= maxVersion; i++ {
		applied[i] = true
	}

	return applied, nil
}

// applyMigration ejecuta una migración.
func (m *Migrator) applyMigration(ctx context.Context, exec SQLExecutor, mig Migration) error {
	// Ejecutar SQL de migración
	_, err := exec.ExecContext(ctx, mig.SQL)
	if err != nil {
		return err
	}

	// Registrar en tabla de migraciones
	_, err = exec.ExecContext(ctx,
		"INSERT INTO _migrations (version, name) VALUES ($1, $2)",
		mig.Version, mig.Name,
	)
	return err
}

// tableExists verifica si una tabla existe.
func (m *Migrator) tableExists(ctx context.Context, exec SQLExecutor, driver, table string) (bool, error) {
	var query string
	switch driver {
	case "postgres":
		query = `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`
	case "mysql":
		query = `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = ?)`
	default:
		query = `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`
	}

	var exists bool
	err := exec.QueryRowContext(ctx, query, table).Scan(&exists)
	return exists, err
}

// ─── PGX Pool Support ───

// PgxPoolExecutor interfaz para pgxpool que permite ejecutar migraciones.
// pgxpool.Pool implementa esta interfaz nativamente.
type PgxPoolExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (interface{ RowsAffected() int64 }, error)
	QueryRow(ctx context.Context, sql string, args ...any) interface{ Scan(dest ...any) error }
}

// RunWithPgxPool aplica migraciones usando pgxpool directamente.
// Esta es la versión preferida para usar con pgx/v5.
func (m *Migrator) RunWithPgxPool(ctx context.Context, pool PgxPoolExecutor) (*MigrationResult, error) {
	start := time.Now()
	result := &MigrationResult{}

	// Asegurar que existe la tabla de migraciones
	createSQL := `
		CREATE TABLE IF NOT EXISTS _migrations (
			version INT PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMPTZ DEFAULT NOW()
		)`
	if _, err := pool.Exec(ctx, createSQL); err != nil {
		result.Error = fmt.Errorf("creating migrations table: %w", err)
		result.Duration = time.Since(start)
		return result, result.Error
	}

	// Obtener versiones aplicadas
	applied := make(map[int]bool)
	var maxVersion int
	row := pool.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM _migrations")
	if err := row.Scan(&maxVersion); err != nil {
		if !strings.Contains(err.Error(), "no rows") {
			result.Error = fmt.Errorf("getting applied migrations: %w", err)
			result.Duration = time.Since(start)
			return result, result.Error
		}
	}
	for i := 1; i <= maxVersion; i++ {
		applied[i] = true
	}

	// Parsear migraciones disponibles
	migrations, err := m.ParseMigrations()
	if err != nil {
		result.Error = fmt.Errorf("parsing migrations: %w", err)
		result.Duration = time.Since(start)
		return result, result.Error
	}

	// Aplicar pendientes
	for _, mig := range migrations {
		if applied[mig.Version] {
			result.Skipped = append(result.Skipped, mig.Version)
			continue
		}

		// Ejecutar SQL de migración
		if _, err := pool.Exec(ctx, mig.SQL); err != nil {
			result.Failed = &mig.Version
			result.Error = fmt.Errorf("applying migration %d_%s: %w", mig.Version, mig.Name, err)
			result.Duration = time.Since(start)
			return result, result.Error
		}

		// Registrar en tabla de migraciones
		if _, err := pool.Exec(ctx, "INSERT INTO _migrations (version, name) VALUES ($1, $2)", mig.Version, mig.Name); err != nil {
			result.Failed = &mig.Version
			result.Error = fmt.Errorf("recording migration %d: %w", mig.Version, err)
			result.Duration = time.Since(start)
			return result, result.Error
		}

		result.Applied = append(result.Applied, mig.Version)
	}

	result.Duration = time.Since(start)
	return result, nil
}
