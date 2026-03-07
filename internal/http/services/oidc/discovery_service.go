package oidc

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/oidc"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// DiscoveryService define las operaciones para OIDC Discovery.
type DiscoveryService interface {
	GetGlobalDiscovery(ctx context.Context) dto.OIDCMetadata
	GetTenantDiscovery(ctx context.Context, slug string) (dto.OIDCMetadata, error)
}

// discoveryService implementa DiscoveryService.
type discoveryService struct {
	baseIssuer string
	cpSvc      controlplane.Service
}

// NewDiscoveryService crea un nuevo servicio de OIDC Discovery.
func NewDiscoveryService(baseIssuer string, cpSvc controlplane.Service) DiscoveryService {
	return &discoveryService{
		baseIssuer: strings.TrimRight(baseIssuer, "/"),
		cpSvc:      cpSvc,
	}
}

const componentDiscovery = "oidc.discovery"

// tenantSlugRe valida slugs: solo a-z, 0-9, - con max 64 chars.
var tenantSlugRe = regexp.MustCompile(`^[a-z0-9\-]{1,64}$`)

// Errores
var (
	ErrInvalidTenantSlug = fmt.Errorf("invalid tenant slug")
	ErrTenantNotFound    = fmt.Errorf("tenant not found")
)

// Metadata OIDC común
var (
	responseTypesSupported            = []string{"code"}
	grantTypesSupported               = []string{"authorization_code", "refresh_token", "client_credentials"}
	subjectTypesSupported             = []string{"public"}
	idTokenSigningAlgValuesSupported  = []string{"EdDSA"}
	tokenEndpointAuthMethodsSupported = []string{"none", "client_secret_post", "client_secret_basic"}
	codeChallengeMethodsSupported     = []string{"S256"}
	scopesSupported                   = []string{"openid", "email", "profile", "offline_access"}
	claimsSupported                   = []string{
		"iss", "sub", "aud", "exp", "iat", "nbf",
		"nonce", "auth_time", "acr", "amr",
		"at_hash", "tid",
		"email", "email_verified",
	}
)

func (s *discoveryService) GetGlobalDiscovery(ctx context.Context) dto.OIDCMetadata {
	return dto.OIDCMetadata{
		Issuer:                            s.baseIssuer,
		AuthorizationEndpoint:             s.baseIssuer + "/oauth2/authorize",
		TokenEndpoint:                     s.baseIssuer + "/oauth2/token",
		UserinfoEndpoint:                  s.baseIssuer + "/userinfo",
		JWKSURI:                           s.baseIssuer + "/.well-known/jwks.json",

		// Endpoints opcionales (RFC 7009, RFC 7662)
		RevocationEndpoint:                s.baseIssuer + "/oauth2/revoke",
		IntrospectionEndpoint:             s.baseIssuer + "/oauth2/introspect",
		// EndSessionEndpoint queda vacío (no implementado aún)

		ResponseTypesSupported:            responseTypesSupported,
		GrantTypesSupported:               grantTypesSupported,
		SubjectTypesSupported:             subjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  idTokenSigningAlgValuesSupported,
		TokenEndpointAuthMethodsSupported: tokenEndpointAuthMethodsSupported,
		CodeChallengeMethodsSupported:     codeChallengeMethodsSupported,
		ScopesSupported:                   scopesSupported,
		ClaimsSupported:                   claimsSupported,
	}
}

func (s *discoveryService) GetTenantDiscovery(ctx context.Context, slug string) (dto.OIDCMetadata, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentDiscovery),
		logger.Op("GetTenantDiscovery"),
		logger.TenantSlug(slug),
	)

	// Validar slug
	if !tenantSlugRe.MatchString(slug) {
		return dto.OIDCMetadata{}, ErrInvalidTenantSlug
	}

	// Obtener tenant
	tenant, err := s.cpSvc.GetTenant(ctx, slug)
	if err != nil {
		log.Error("failed to get tenant", logger.Err(err))
		return dto.OIDCMetadata{}, ErrTenantNotFound
	}

	// Resolver issuer para este tenant
	iss := jwtx.ResolveIssuer(
		s.baseIssuer,
		string(tenant.Settings.IssuerMode),
		slug,
		tenant.Settings.IssuerOverride,
	)

	// Endpoints globales para compat, solo issuer y jwks_uri son por tenant
	return dto.OIDCMetadata{
		Issuer:                            iss,
		AuthorizationEndpoint:             s.baseIssuer + "/oauth2/authorize",
		TokenEndpoint:                     s.baseIssuer + "/oauth2/token",
		UserinfoEndpoint:                  s.baseIssuer + "/userinfo",
		JWKSURI:                           s.baseIssuer + "/.well-known/jwks/" + slug + ".json",

		// Endpoints opcionales (RFC 7009, RFC 7662)
		RevocationEndpoint:                s.baseIssuer + "/oauth2/revoke",
		IntrospectionEndpoint:             s.baseIssuer + "/oauth2/introspect",
		// EndSessionEndpoint queda vacío (no implementado aún)

		ResponseTypesSupported:            responseTypesSupported,
		GrantTypesSupported:               grantTypesSupported,
		SubjectTypesSupported:             subjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  idTokenSigningAlgValuesSupported,
		TokenEndpointAuthMethodsSupported: tokenEndpointAuthMethodsSupported,
		CodeChallengeMethodsSupported:     codeChallengeMethodsSupported,
		ScopesSupported:                   scopesSupported,
		ClaimsSupported:                   claimsSupported,
	}, nil
}
