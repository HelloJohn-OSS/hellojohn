package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/security"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// CSRFService defines operations for CSRF token management.
type CSRFService interface {
	GenerateToken(ctx context.Context) (*CSRFResult, error)
}

// CSRFResult contains the generated token and cookie details.
type CSRFResult struct {
	Token      string
	CookieName string
	ExpiresAt  time.Time
	Secure     bool
}

// CSRFDeps contains dependencies for the CSRF service.
type CSRFDeps struct {
	Config dto.CSRFConfig
}

type csrfService struct {
	config dto.CSRFConfig
}

// NewCSRFService creates a new CSRFService.
func NewCSRFService(deps CSRFDeps) CSRFService {
	cfg := deps.Config
	// Apply defaults
	if cfg.CookieName == "" {
		cfg.CookieName = "csrf_token"
	}
	if cfg.TTLSeconds <= 0 {
		cfg.TTLSeconds = 1800 // 30 minutes
	}
	return &csrfService{config: cfg}
}

// Service errors
var (
	ErrCSRFTokenGeneration = fmt.Errorf("failed to generate CSRF token")
)

// GenerateToken generates a new CSRF token.
func (s *csrfService) GenerateToken(ctx context.Context) (*CSRFResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("security.csrf"),
		logger.Op("GenerateToken"),
	)

	// Generate 32 random bytes
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Error("failed to generate random bytes", logger.Err(err))
		return nil, ErrCSRFTokenGeneration
	}

	token := hex.EncodeToString(b[:])
	expiresAt := time.Now().Add(time.Duration(s.config.TTLSeconds) * time.Second).UTC()

	log.Debug("csrf token generated")

	return &CSRFResult{
		Token:      token,
		CookieName: s.config.CookieName,
		ExpiresAt:  expiresAt,
		Secure:     s.config.Secure,
	}, nil
}
