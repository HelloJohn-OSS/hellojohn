// Package oidc contiene los services para endpoints OIDC/Discovery.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// JWKSService define las operaciones para obtener JWKS.
type JWKSService interface {
	GetGlobalJWKS(ctx context.Context) (json.RawMessage, error)
	GetTenantJWKS(ctx context.Context, slug string) (json.RawMessage, error)
}

// jwksService implementa JWKSService.
type jwksService struct {
	cache *jwtx.JWKSCache
}

// NewJWKSService crea un nuevo servicio JWKS.
func NewJWKSService(cache *jwtx.JWKSCache) JWKSService {
	return &jwksService{cache: cache}
}

const componentJWKS = "oidc.jwks"

// slugRe valida slugs de tenant: solo a-z, 0-9, - con max 64 chars.
var slugRe = regexp.MustCompile(`^[a-z0-9\-]{1,64}$`)

// uuidRe valida UUIDs (formato: 8-4-4-4-12 hex chars con guiones)
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrInvalidSlug indica que el slug/ID es inválido.
var ErrInvalidSlug = fmt.Errorf("invalid slug or ID format")

func (s *jwksService) GetGlobalJWKS(ctx context.Context) (json.RawMessage, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentJWKS),
		logger.Op("GetGlobalJWKS"),
	)

	data, err := s.cache.Get("global")
	if err != nil {
		log.Error("failed to get global JWKS", logger.Err(err))
		return nil, err
	}

	return data, nil
}

func (s *jwksService) GetTenantJWKS(ctx context.Context, slugOrID string) (json.RawMessage, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentJWKS),
		logger.Op("GetTenantJWKS"),
		logger.TenantSlug(slugOrID),
	)

	// Validar que sea un slug válido o un UUID
	if !slugRe.MatchString(slugOrID) && !uuidRe.MatchString(slugOrID) {
		log.Error("invalid tenant identifier format", logger.String("tenant", slugOrID))
		return nil, ErrInvalidSlug
	}

	// El cache se encargará de resolver el tenant por slug o ID
	data, err := s.cache.Get(slugOrID)
	if err != nil {
		log.Error("failed to get tenant JWKS", logger.Err(err))
		return nil, err
	}

	return data, nil
}
