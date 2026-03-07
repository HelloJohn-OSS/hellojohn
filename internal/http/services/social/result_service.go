package social

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/social"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

// ResultService defines operations for social result viewing.
type ResultService interface {
	GetResult(ctx context.Context, req dto.ResultRequest) (*dto.ResultResponse, error)
}

type resultService struct {
	cache     Cache
	debugPeek bool // If true, allow peek mode
}

// ResultDeps contains dependencies for the result service.
type ResultDeps struct {
	Cache     Cache
	DebugPeek bool // Enable peek mode (should be false in production)
}

// NewResultService creates a new ResultService.
func NewResultService(deps ResultDeps) ResultService {
	return &resultService{
		cache:     deps.Cache,
		debugPeek: deps.DebugPeek,
	}
}

// Service errors
var (
	ErrResultCodeMissing  = fmt.Errorf("code is required")
	ErrResultCodeNotFound = fmt.Errorf("code not found or expired")
)

// GetResult retrieves a social login code result from cache.
func (s *resultService) GetResult(ctx context.Context, req dto.ResultRequest) (*dto.ResultResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("social.result"),
		logger.Op("GetResult"),
	)

	code := strings.TrimSpace(req.Code)
	if code == "" {
		return nil, ErrResultCodeMissing
	}

	// Peek mode only allowed if debugPeek is enabled
	peek := req.Peek && s.debugPeek

	key := "social:code:" + code
	payload, ok := s.cache.Get(key)
	if !ok || len(payload) == 0 {
		log.Debug("code not found", zap.String("key_prefix", "social:code:"))
		return nil, ErrResultCodeNotFound
	}

	// Consume code unless in peek mode
	if !peek {
		if err := s.cache.Delete(key); err != nil {
			log.Debug("failed to delete code from cache", logger.Err(err))
		}
	}

	log.Debug("social result retrieved",
		zap.Bool("peek", peek),
	)

	return &dto.ResultResponse{
		Code:       code,
		Payload:    payload,
		PayloadB64: base64.StdEncoding.EncodeToString(payload),
		Peek:       peek,
	}, nil
}
