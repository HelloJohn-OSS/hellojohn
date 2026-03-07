package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

const (
	importStatusProcessing = "processing"
	importStatusCompleted  = "completed"
	importStatusFailed     = "failed"
	importBatchSize        = 500
)

// ImportService maneja imports masivos de usuarios en background.
type ImportService interface {
	StartImport(ctx context.Context, tenantID string, body io.Reader) (jobID string, err error)
	GetImportStatus(ctx context.Context, jobID string) (*dto.UserImportStatusResponse, error)
}

// ImportDeps contiene dependencias del servicio de import.
type ImportDeps struct {
	DAL store.DataAccessLayer
}

type importService struct {
	deps ImportDeps
	jobs sync.Map // map[string]*importJob
}

type importJob struct {
	mu        sync.RWMutex
	jobID     string
	status    string
	total     int
	created   int
	failed    int
	errorLog  []dto.UserImportStatusError
	createdAt time.Time
	updatedAt time.Time
}

var ErrImportJobNotFound = errors.New("import job not found")

// NewImportService crea el servicio de import.
func NewImportService(deps ImportDeps) ImportService {
	return &importService{deps: deps}
}

func (s *importService) StartImport(_ context.Context, tenantID string, body io.Reader) (string, error) {
	rawID, err := tokens.GenerateOpaqueToken(16)
	if err != nil {
		return "", fmt.Errorf("generate import job id: %w", err)
	}
	jobID := rawID

	tmp, err := os.CreateTemp("", "hellojohn-user-import-*.json")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("copy import payload: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temp file: %w", err)
	}

	now := time.Now().UTC()
	job := &importJob{
		jobID:     jobID,
		status:    importStatusProcessing,
		createdAt: now,
		updatedAt: now,
	}
	s.jobs.Store(jobID, job)

	go s.processImport(tenantID, tmpPath, job)
	return jobID, nil
}

func (s *importService) GetImportStatus(_ context.Context, jobID string) (*dto.UserImportStatusResponse, error) {
	val, ok := s.jobs.Load(jobID)
	if !ok {
		return nil, ErrImportJobNotFound
	}

	job, ok := val.(*importJob)
	if !ok {
		return nil, ErrImportJobNotFound
	}

	job.mu.RLock()
	defer job.mu.RUnlock()

	return &dto.UserImportStatusResponse{
		JobID:     job.jobID,
		Status:    job.status,
		Total:     job.total,
		Created:   job.created,
		Failed:    job.failed,
		ErrorLog:  append([]dto.UserImportStatusError(nil), job.errorLog...),
		CreatedAt: job.createdAt.Format(time.RFC3339),
		UpdatedAt: job.updatedAt.Format(time.RFC3339),
	}, nil
}

func (s *importService) processImport(tenantRef, filePath string, job *importJob) {
	defer func() {
		_ = os.Remove(filePath)
	}()

	f, err := os.Open(filePath)
	if err != nil {
		s.markFailed(job, fmt.Sprintf("open import file: %v", err))
		return
	}
	defer f.Close()

	tda, err := s.deps.DAL.ForTenant(context.Background(), tenantRef)
	if err != nil {
		s.markFailed(job, fmt.Sprintf("resolve tenant: %v", err))
		return
	}
	if err := tda.RequireDB(); err != nil {
		s.markFailed(job, fmt.Sprintf("tenant requires db: %v", err))
		return
	}

	dec := json.NewDecoder(f)
	if err := advanceToUsersArray(dec); err != nil {
		s.markFailed(job, fmt.Sprintf("invalid import payload: %v", err))
		return
	}

	var (
		line  int
		batch []repository.CreateUserInput
	)

	for dec.More() {
		line++
		s.incrementTotal(job)

		var rec dto.UserImportRecord
		if err := dec.Decode(&rec); err != nil {
			s.markFailed(job, fmt.Sprintf("decode user record at line %d: %v", line, err))
			return
		}

		rec.Email = strings.TrimSpace(strings.ToLower(rec.Email))
		if rec.Email == "" {
			s.appendRecordError(job, dto.UserImportStatusError{
				Line:  line,
				Error: "email is required",
			})
			continue
		}
		if strings.TrimSpace(rec.PasswordHash) == "" {
			s.appendRecordError(job, dto.UserImportStatusError{
				Line:  line,
				Email: rec.Email,
				Error: "password_hash is required",
			})
			continue
		}

		batch = append(batch, mapImportRecordToCreateInput(rec, tda.ID()))
		if len(batch) >= importBatchSize {
			if err := s.flushBatch(context.Background(), tda, batch, job); err != nil {
				s.markFailed(job, fmt.Sprintf("insert batch: %v", err))
				return
			}
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		if err := s.flushBatch(context.Background(), tda, batch, job); err != nil {
			s.markFailed(job, fmt.Sprintf("insert final batch: %v", err))
			return
		}
	}

	job.mu.Lock()
	job.status = importStatusCompleted
	job.updatedAt = time.Now().UTC()
	job.mu.Unlock()
}

func (s *importService) flushBatch(ctx context.Context, tda store.TenantDataAccess, batch []repository.CreateUserInput, job *importJob) error {
	created, failed, err := tda.Users().CreateBatch(ctx, tda.ID(), batch)
	if err != nil {
		return err
	}

	job.mu.Lock()
	job.created += created
	job.failed += failed
	job.updatedAt = time.Now().UTC()
	job.mu.Unlock()
	return nil
}

func (s *importService) incrementTotal(job *importJob) {
	job.mu.Lock()
	job.total++
	job.updatedAt = time.Now().UTC()
	job.mu.Unlock()
}

func (s *importService) appendRecordError(job *importJob, item dto.UserImportStatusError) {
	job.mu.Lock()
	job.failed++
	job.errorLog = append(job.errorLog, item)
	job.updatedAt = time.Now().UTC()
	job.mu.Unlock()
}

func (s *importService) markFailed(job *importJob, reason string) {
	job.mu.Lock()
	job.status = importStatusFailed
	job.errorLog = append(job.errorLog, dto.UserImportStatusError{Error: reason})
	job.updatedAt = time.Now().UTC()
	job.mu.Unlock()
}

func advanceToUsersArray(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}

	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("expected object root")
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}

		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected object key")
		}

		if key == "users" {
			arrTok, err := dec.Token()
			if err != nil {
				return err
			}
			arrDelim, ok := arrTok.(json.Delim)
			if !ok || arrDelim != '[' {
				return fmt.Errorf("users must be an array")
			}
			return nil
		}

		var ignored any
		if err := dec.Decode(&ignored); err != nil {
			return err
		}
	}

	return fmt.Errorf("users key not found")
}

func mapImportRecordToCreateInput(rec dto.UserImportRecord, tenantID string) repository.CreateUserInput {
	customFields := map[string]any{}
	for k, v := range rec.Metadata {
		customFields[k] = v
	}

	return repository.CreateUserInput{
		TenantID:     tenantID,
		Email:        rec.Email,
		PasswordHash: rec.PasswordHash, // externo, no se re-hashea
		Name:         strings.TrimSpace(rec.Name),
		CustomFields: customFields,
		Provider:     "password",
	}
}
