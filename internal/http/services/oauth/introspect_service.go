package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/oauth"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// IntrospectService defines operations for token introspection.
type IntrospectService interface {
	Introspect(ctx context.Context, token string, includeSys bool) (*dto.IntrospectResult, error)
}

// IntrospectDeps contains dependencies for the introspect service.
type IntrospectDeps struct {
	DAL    store.DataAccessLayer
	Issuer *jwtx.Issuer
}

type introspectService struct {
	deps IntrospectDeps
}

// NewIntrospectService creates a new IntrospectService.
func NewIntrospectService(deps IntrospectDeps) IntrospectService {
	return &introspectService{deps: deps}
}

// Service errors
var (
	ErrIntrospectTokenEmpty = fmt.Errorf("token is empty")
)

// Introspect analyzes a token and returns its status and claims.
// Always returns a result (never nil) - inactive tokens return active=false.
func (s *introspectService) Introspect(ctx context.Context, token string, includeSys bool) (*dto.IntrospectResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("oauth.introspect"),
		logger.Op("Introspect"),
	)

	if token == "" {
		return nil, ErrIntrospectTokenEmpty
	}

	// Determine token type by heuristic:
	// - Refresh opaque: length >= 40 and no dots
	// - JWT: contains dots
	isOpaque := len(token) >= 40 && !strings.Contains(token, ".")

	if isOpaque {
		return s.introspectRefreshToken(ctx, token, log)
	}

	return s.introspectJWT(ctx, token, includeSys, log)
}

// introspectRefreshToken handles opaque refresh token introspection.
func (s *introspectService) introspectRefreshToken(ctx context.Context, token string, log *zap.Logger) (*dto.IntrospectResult, error) {
	hash := tokens.SHA256Base64URL(token)

	// Search for token in all tenants
	tenants, err := s.deps.DAL.ConfigAccess().Tenants().List(ctx)
	if err != nil {
		log.Debug("failed to list tenants", logger.Err(err))
		return &dto.IntrospectResult{Active: false}, nil
	}

	for _, t := range tenants {
		tda, err := s.deps.DAL.ForTenant(ctx, t.Slug)
		if err != nil {
			continue
		}

		if tda.RequireDB() != nil {
			continue
		}

		rt, err := tda.Tokens().GetByHash(ctx, hash)
		if err != nil || rt == nil {
			continue
		}

		// Found the token
		active := rt.RevokedAt == nil && rt.ExpiresAt.After(time.Now().UTC())

		log.Debug("refresh token introspected",
			zap.Bool("active", active),
			zap.String("user_id", rt.UserID),
		)

		return &dto.IntrospectResult{
			Active:    active,
			TokenType: "refresh_token",
			Sub:       rt.UserID,
			ClientID:  rt.ClientID,
			Exp:       rt.ExpiresAt.Unix(),
			Iat:       rt.IssuedAt.Unix(),
		}, nil
	}

	// Token not found
	log.Debug("refresh token not found")
	return &dto.IntrospectResult{Active: false}, nil
}

// introspectJWT handles JWT access token introspection.
func (s *introspectService) introspectJWT(ctx context.Context, token string, includeSys bool, log *zap.Logger) (*dto.IntrospectResult, error) {
	// Parse and validate JWT
	parsed, err := jwtv5.Parse(token, s.deps.Issuer.KeyfuncFromTokenClaims(), jwtv5.WithValidMethods([]string{"EdDSA"}))
	if err != nil || !parsed.Valid {
		log.Debug("jwt parse failed", logger.Err(err))
		return &dto.IntrospectResult{Active: false}, nil
	}

	claims, ok := parsed.Claims.(jwtv5.MapClaims)
	if !ok {
		return &dto.IntrospectResult{Active: false}, nil
	}

	// Extract claims
	expF, _ := claims["exp"].(float64)
	iatF, _ := claims["iat"].(float64)
	sub, _ := claims["sub"].(string)
	clientID, _ := claims["aud"].(string)
	tid, _ := claims["tid"].(string)
	acr, _ := claims["acr"].(string)
	iss, _ := claims["iss"].(string)
	jti, _ := claims["jti"].(string)

	// Extract scope (support both "scope" and "scp")
	scopeRaw, _ := claims["scope"].(string)
	if scopeRaw == "" {
		if scp, ok := claims["scp"].(string); ok {
			scopeRaw = scp
		}
	}

	// Extract AMR
	var amrVals []string
	if amr, ok := claims["amr"].([]any); ok {
		for _, v := range amr {
			if s, ok := v.(string); ok {
				amrVals = append(amrVals, s)
			}
		}
	}

	// Check if token is active (not expired)
	active := time.Unix(int64(expF), 0).After(time.Now())

	// Validate issuer against expected issuer for tenant
	if active && iss != "" && tid != "" {
		// Look up tenant from config
		tenant, err := s.deps.DAL.ConfigAccess().Tenants().GetBySlug(ctx, tid)
		if err == nil && tenant != nil {
			expected := jwtx.ResolveIssuer(
				s.deps.Issuer.Iss,
				string(tenant.Settings.IssuerMode),
				tenant.Slug,
				tenant.Settings.IssuerOverride,
			)
			if expected != iss {
				log.Debug("issuer mismatch",
					zap.String("expected", expected),
					zap.String("got", iss),
				)
				active = false
			}
		}
	}

	result := &dto.IntrospectResult{
		Active:    active,
		TokenType: "access_token",
		Sub:       sub,
		ClientID:  clientID,
		Scope:     scopeRaw,
		Exp:       int64(expF),
		Iat:       int64(iatF),
		Iss:       iss,
		Jti:       jti,
		Tid:       tid,
		Acr:       acr,
		Amr:       amrVals,
	}

	// Extract system roles/perms if requested and token is active
	if active && includeSys {
		result.Roles, result.Perms = s.extractSystemClaims(claims, log)
	}

	log.Debug("jwt introspected",
		zap.Bool("active", active),
		zap.String("sub", sub),
	)

	return result, nil
}

// extractSystemClaims extracts roles and perms from the custom namespace.
func (s *introspectService) extractSystemClaims(claims jwtv5.MapClaims, log *zap.Logger) ([]string, []string) {
	custom, ok := claims["custom"].(map[string]any)
	if !ok {
		return nil, nil
	}

	var roles, perms []string

	// Try system namespace first
	sysNS := s.deps.Issuer.Iss + ":sys"
	if sys, ok := custom[sysNS].(map[string]any); ok {
		roles = s.extractStringSlice(sys["roles"])
		perms = s.extractStringSlice(sys["perms"])
	} else if sys, ok := custom[s.deps.Issuer.Iss].(map[string]any); ok {
		// Fallback: legacy format
		roles = s.extractStringSlice(sys["roles"])
		perms = s.extractStringSlice(sys["perms"])
	}

	return roles, perms
}

// extractStringSlice normalizes []any or []string to []string.
func (s *introspectService) extractStringSlice(v any) []string {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case []any:
		var result []string
		for _, item := range val {
			if str, ok := item.(string); ok && str != "" {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return val
	}

	return nil
}
