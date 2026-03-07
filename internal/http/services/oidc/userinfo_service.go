package oidc

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/oidc"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// UserInfoService define las operaciones para OIDC UserInfo.
type UserInfoService interface {
	GetUserInfo(ctx context.Context, bearerToken string) (*dto.UserInfoResponse, error)
}

// UserInfoDeps contiene las dependencias para UserInfo service.
type UserInfoDeps struct {
	Issuer       *jwtx.Issuer
	ControlPlane controlplane.Service
	DAL          store.DataAccessLayer
}

type userInfoService struct {
	deps UserInfoDeps
}

// NewUserInfoService crea un nuevo servicio UserInfo.
func NewUserInfoService(deps UserInfoDeps) UserInfoService {
	return &userInfoService{deps: deps}
}

// Errores de UserInfo
var (
	ErrMissingToken   = fmt.Errorf("missing bearer token")
	ErrInvalidToken   = fmt.Errorf("invalid or expired token")
	ErrIssuerMismatch = fmt.Errorf("issuer mismatch")
	ErrMissingSub     = fmt.Errorf("missing sub claim")
)

func (s *userInfoService) GetUserInfo(ctx context.Context, bearerToken string) (*dto.UserInfoResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("oidc.userinfo"),
		logger.Op("GetUserInfo"),
	)

	// 1) Validar token JWT
	tk, err := jwtv5.Parse(bearerToken, s.deps.Issuer.Keyfunc(), jwtv5.WithValidMethods([]string{"EdDSA"}))
	if err != nil || !tk.Valid {
		log.Debug("invalid token", logger.Err(err))
		return nil, ErrInvalidToken
	}

	claims, ok := tk.Claims.(jwtv5.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// 2) Validar issuer per-tenant
	issStr, _ := claims["iss"].(string)
	if issStr != "" && s.deps.ControlPlane != nil {
		slug := extractSlugFromIssuer(issStr)
		if slug != "" {
			tenant, err := s.deps.ControlPlane.GetTenant(ctx, slug)
			if err == nil && tenant != nil {
				expected := jwtx.ResolveIssuer(
					s.deps.Issuer.Iss,
					string(tenant.Settings.IssuerMode),
					tenant.Slug,
					tenant.Settings.IssuerOverride,
				)
				if expected != issStr {
					log.Debug("issuer mismatch", logger.String("expected", expected), logger.String("actual", issStr))
					return nil, ErrIssuerMismatch
				}
			}
		}
	}

	// 3) Extraer sub
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, ErrMissingSub
	}

	// 4) Extraer scopes (soporta múltiples formatos)
	scopes := helpers.ExtractScopesFromMapClaims(claims)

	// 5) Resolver tenant store
	tid, _ := claims["tid"].(string)
	tda := s.resolveTenantStore(ctx, tid)

	// 6) Obtener usuario
	resp := &dto.UserInfoResponse{
		Sub:          sub,
		CustomFields: make(map[string]any),
	}

	if tda != nil {
		user, err := tda.Users().GetByID(ctx, sub)
		if err == nil && user != nil {
			s.populateUserInfo(resp, user, scopes)
		} else if err != nil {
			log.Debug("user not found", logger.Err(err))
		}
	}

	return resp, nil
}

func (s *userInfoService) resolveTenantStore(ctx context.Context, tid string) store.TenantDataAccess {
	if tid == "" || s.deps.DAL == nil {
		return nil
	}
	// DAL.ForTenant acepta slug o UUID indistintamente.
	// No es necesaria la conversión previa UUID→slug via ControlPlane.
	tda, err := s.deps.DAL.ForTenant(ctx, tid)
	if err != nil {
		return nil
	}
	return tda
}

func (s *userInfoService) populateUserInfo(resp *dto.UserInfoResponse, user *repository.User, scopes []string) {
	// Standard OIDC claims
	if user.Name != "" {
		resp.Name = user.Name
	}
	if user.GivenName != "" {
		resp.GivenName = user.GivenName
	}
	if user.FamilyName != "" {
		resp.FamilyName = user.FamilyName
	}
	if user.Picture != "" {
		resp.Picture = user.Picture
	}
	if user.Locale != "" {
		resp.Locale = user.Locale
	}

	// Email solo si scope "email" presente
	if helpers.HasScope(scopes, "email") {
		resp.Email = user.Email
		resp.EmailVerified = user.EmailVerified
	}

	// Custom fields siempre (para CompleteProfile flow)
	finalCF := make(map[string]any)

	// 1. From Metadata (legacy)
	if user.Metadata != nil {
		if cf, ok := user.Metadata["custom_fields"].(map[string]any); ok {
			for k, v := range cf {
				finalCF[k] = v
			}
		}
	}

	// 2. From CustomFields (columnas dinámicas) - tienen precedencia
	if user.CustomFields != nil {
		for k, v := range user.CustomFields {
			finalCF[k] = v
		}
	}

	resp.CustomFields = finalCF
}

// ─── Internal Helpers ───
// Nota: helpers comunes (scopes, hasScope) están en internal/http/v2/helpers/

func extractSlugFromIssuer(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "t" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
