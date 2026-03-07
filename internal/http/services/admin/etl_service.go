package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// EtlService errors.
var (
	ErrEtlNotAvailable = errors.New("ETL migration not available: no global database configured")
	ErrEtlJobNotFound  = errors.New("migration job not found")
)

// EtlService gestiona trabajos de migración de datos entre bases de datos de tenant.
// La migración de esquema es responsabilidad de MigrateService; EtlService maneja
// el copiado asíncrono de datos (usuarios, tokens, consentimientos, roles…).
type EtlService interface {
	// StartMigration inicia una migración asíncrona de datos para el tenant.
	// Crea un MigrationJob y lanza una goroutine que copia los datos.
	StartMigration(ctx context.Context, tenantID, targetDSN, driver string) (*repository.MigrationJob, error)
	// ListJobs lista todos los trabajos de migración de un tenant.
	ListJobs(ctx context.Context, tenantID string) ([]repository.MigrationJob, error)
	// GetJobStatus retorna el trabajo de migración por ID.
	GetJobStatus(ctx context.Context, tenantID, jobID string) (*repository.MigrationJob, error)
}

// EtlDeps dependencias para crear el EtlService.
type EtlDeps struct {
	DAL     store.DataAccessLayer
	JobRepo repository.MigrationJobRepository // nil si no hay global DB
	BaseURL string
}

type etlService struct {
	deps EtlDeps
}

// NewEtlService crea el EtlService. JobRepo puede ser nil (sin global DB).
func NewEtlService(deps EtlDeps) EtlService {
	return &etlService{deps: deps}
}

// compile-time check
var _ EtlService = (*etlService)(nil)

func (s *etlService) StartMigration(ctx context.Context, tenantID, targetDSN, driver string) (*repository.MigrationJob, error) {
	if s.deps.JobRepo == nil {
		return nil, ErrEtlNotAvailable
	}
	if targetDSN == "" {
		return nil, ErrMigrateDSNEmpty
	}
	if driver == "" {
		driver = "postgres"
	}

	// Validar que el tenant existe
	if s.deps.DAL != nil {
		_, err := s.deps.DAL.ForTenant(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("resolve tenant: %w", err)
		}
	}

	job := repository.MigrationJob{
		ID:         uuid.New().String(),
		TenantID:   tenantID,
		Type:       "etl_data_copy",
		Status:     "pending",
		SourceInfo: fmt.Sprintf("tenant:%s", tenantID),
		TargetInfo: fmt.Sprintf("driver:%s", driver),
		StartedAt:  time.Now(),
	}

	if err := s.deps.JobRepo.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("create migration job: %w", err)
	}

	// Lanzar migración asíncrona. Usa context.Background() para no cancelar
	// si la petición HTTP termina.
	go s.runMigration(context.Background(), job.ID, tenantID, targetDSN, driver)

	return &job, nil
}

func (s *etlService) runMigration(ctx context.Context, jobID, tenantID, targetDSN, driver string) {
	log := logger.L().With(
		logger.String("job_id", jobID),
		logger.String("tenant", tenantID),
	)
	log.Info("etl_service: starting data migration")

	// Helper para marcar el job como fallido.
	fail := func(msg string, err error) {
		log.Error(msg, logger.Err(err))
		if ferr := s.deps.JobRepo.Fail(ctx, jobID, fmt.Sprintf("%s: %v", msg, err)); ferr != nil {
			log.Error("etl_service: failed to update job status", logger.Err(ferr))
		}
	}

	// Actualizar a "running" — UpdateProgress solo toma el porcentaje;
	// el status se actualiza via Complete/Fail.
	if err := s.deps.JobRepo.UpdateProgress(ctx, jobID, 0); err != nil {
		log.Error("etl_service: could not update job to running", logger.Err(err))
	}

	// Abrir conexión al destino
	targetConn, err := store.OpenAdapter(ctx, store.AdapterConfig{
		Name: driver,
		DSN:  targetDSN,
	})
	if err != nil {
		fail("open target connection", err)
		return
	}
	defer targetConn.Close()

	// Copiar tabla por tabla. MVP: solo conteo de filas como progreso.
	// La implementación real copiará cada tabla con batches.
	tables := []struct {
		name string
		pct  int
	}{
		{"app_user", 25},
		{"identity", 50},
		{"refresh_token", 70},
		{"rbac_user_role", 85},
		{"consent", 95},
	}

	for _, t := range tables {
		log.Info("etl_service: copying table", logger.String("table", t.name))
		// TODO: implementar copia real con pgx.CopyFrom / INSERT batches.
		// Por ahora solo actualiza progreso para validación end-to-end del flujo.
		if err := s.deps.JobRepo.UpdateProgress(ctx, jobID, t.pct); err != nil {
			log.Error("etl_service: could not update progress", logger.Err(err))
		}
	}

	// Completar
	if err := s.deps.JobRepo.Complete(ctx, jobID); err != nil {
		log.Error("etl_service: could not mark job complete", logger.Err(err))
		return
	}
	log.Info("etl_service: migration completed", logger.String("tenant", tenantID))
}

func (s *etlService) ListJobs(ctx context.Context, tenantID string) ([]repository.MigrationJob, error) {
	if s.deps.JobRepo == nil {
		return nil, ErrEtlNotAvailable
	}
	return s.deps.JobRepo.ListByTenant(ctx, tenantID)
}

func (s *etlService) GetJobStatus(ctx context.Context, tenantID, jobID string) (*repository.MigrationJob, error) {
	if s.deps.JobRepo == nil {
		return nil, ErrEtlNotAvailable
	}
	job, err := s.deps.JobRepo.GetByID(ctx, jobID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrEtlJobNotFound
		}
		return nil, err
	}
	// Verificar que el job pertenece al tenant solicitado
	if job.TenantID != tenantID {
		return nil, ErrEtlJobNotFound
	}
	return job, nil
}
