package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/claims"
	"github.com/dropDatabas3/hellojohn/internal/claims/resolver"
	"github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// ClaimsService define las operaciones de claims para el admin API.
type ClaimsService interface {
	GetConfig(ctx context.Context, tenantSlug string) (*dto.ClaimsConfigResponse, error)
	ListCustomClaims(ctx context.Context, tenantSlug string) ([]dto.ClaimResponse, error)
	CreateCustomClaim(ctx context.Context, tenantSlug string, req dto.ClaimCreateRequest) (*dto.ClaimResponse, error)
	GetCustomClaim(ctx context.Context, tenantSlug, claimID string) (*dto.ClaimResponse, error)
	UpdateCustomClaim(ctx context.Context, tenantSlug, claimID string, req dto.ClaimUpdateRequest) (*dto.ClaimResponse, error)
	DeleteCustomClaim(ctx context.Context, tenantSlug, claimID string) error
	ToggleStandardClaim(ctx context.Context, tenantSlug, claimName string, enabled bool) error
	GetSettings(ctx context.Context, tenantSlug string) (*dto.ClaimsSettingsResponse, error)
	UpdateSettings(ctx context.Context, tenantSlug string, req dto.ClaimsSettingsUpdateRequest) (*dto.ClaimsSettingsResponse, error)
	GetScopeMappings(ctx context.Context, tenantSlug string) ([]dto.ScopeMappingResponse, error)

	// Playground Interactivo GUI
	EvaluatePlayground(ctx context.Context, tenantSlug string, req dto.ClaimPlaygroundRequest) (*dto.ClaimPlaygroundResponse, error)
}

type claimsService struct {
	cp controlplane.Service
}

// NewClaimsService crea un nuevo servicio de claims.
func NewClaimsService(cp controlplane.Service) ClaimsService {
	return &claimsService{cp: cp}
}

const componentClaims = "admin.claims"

func (s *claimsService) GetConfig(ctx context.Context, tenantSlug string) (*dto.ClaimsConfigResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("GetConfig"),
		logger.TenantSlug(tenantSlug),
	)

	config, err := s.cp.GetClaimsConfig(ctx, tenantSlug)
	if err != nil {
		log.Error("failed to get claims config", logger.Err(err))
		return nil, err
	}

	// Map scope mappings
	mappings, err := s.cp.GetScopeMappings(ctx, tenantSlug)
	if err != nil {
		log.Error("failed to get scope mappings", logger.Err(err))
		return nil, err
	}

	// Convert to DTOs
	standardClaims := make([]dto.StandardClaimResponse, len(config.StandardClaims))
	for i, sc := range config.StandardClaims {
		standardClaims[i] = dto.StandardClaimResponse{
			Name:        sc.ClaimName,
			Description: sc.Description,
			Enabled:     sc.Enabled,
			Scope:       sc.Scope,
		}
	}

	customClaims := make([]dto.ClaimResponse, len(config.CustomClaims))
	for i, cc := range config.CustomClaims {
		customClaims[i] = toClaimResponse(cc)
	}

	scopeMappings := make([]dto.ScopeMappingResponse, len(mappings))
	for i, m := range mappings {
		scopeMappings[i] = dto.ScopeMappingResponse{
			Scope:  m.Scope,
			Claims: m.Claims,
		}
	}

	return &dto.ClaimsConfigResponse{
		StandardClaims: standardClaims,
		CustomClaims:   customClaims,
		ScopeMappings:  scopeMappings,
		Settings: dto.ClaimsSettingsResponse{
			IncludeInAccessToken: config.Settings.IncludeInAccessToken,
			UseNamespacedClaims:  config.Settings.UseNamespacedClaims,
			NamespacePrefix:      config.Settings.NamespacePrefix,
		},
	}, nil
}

func (s *claimsService) ListCustomClaims(ctx context.Context, tenantSlug string) ([]dto.ClaimResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("ListCustomClaims"),
		logger.TenantSlug(tenantSlug),
	)

	claims, err := s.cp.ListCustomClaims(ctx, tenantSlug)
	if err != nil {
		log.Error("failed to list custom claims", logger.Err(err))
		return nil, err
	}

	result := make([]dto.ClaimResponse, len(claims))
	for i, c := range claims {
		result[i] = toClaimResponse(c)
	}
	return result, nil
}

func (s *claimsService) CreateCustomClaim(ctx context.Context, tenantSlug string, req dto.ClaimCreateRequest) (*dto.ClaimResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("CreateCustomClaim"),
		logger.TenantSlug(tenantSlug),
	)

	// JSON SCHEMA VALIDATION (Fase 6.5 - Anti-Malformaciones)
	// Aborta el guardado si el admin carga un Webhook o Script CEL roto.
	if err := claims.ValidateClaimConfig(req.Source, req.ConfigData); err != nil {
		log.Warn("json schema claim config rejected", logger.Err(err))
		return nil, fmt.Errorf("configuración malformada para resolver '%s': %w", req.Source, err)
	}

	input := repository.ClaimInput{
		Name:          req.Name,
		Description:   req.Description,
		Source:        req.Source,
		Value:         req.Value,
		AlwaysInclude: req.AlwaysInclude,
		Scopes:        req.Scopes,
		Enabled:       req.Enabled,
		Required:      req.Required,
		ConfigData:    req.ConfigData,
	}

	claim, err := s.cp.CreateCustomClaim(ctx, tenantSlug, input)
	if err != nil {
		log.Error("failed to create custom claim", logger.Err(err))
		return nil, err
	}

	log.Info("custom claim created", logger.String("claim_name", claim.Name))
	resp := toClaimResponse(*claim)
	return &resp, nil
}

func (s *claimsService) GetCustomClaim(ctx context.Context, tenantSlug, claimID string) (*dto.ClaimResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("GetCustomClaim"),
		logger.TenantSlug(tenantSlug),
	)

	claim, err := s.cp.GetCustomClaim(ctx, tenantSlug, claimID)
	if err != nil {
		log.Error("failed to get custom claim", logger.Err(err))
		return nil, err
	}

	resp := toClaimResponse(*claim)
	return &resp, nil
}

func (s *claimsService) UpdateCustomClaim(ctx context.Context, tenantSlug, claimID string, req dto.ClaimUpdateRequest) (*dto.ClaimResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("UpdateCustomClaim"),
		logger.TenantSlug(tenantSlug),
	)

	// Get existing claim
	existing, err := s.cp.GetCustomClaim(ctx, tenantSlug, claimID)
	if err != nil {
		log.Error("failed to get existing claim", logger.Err(err))
		return nil, err
	}

	// Build input with updates
	input := repository.ClaimInput{
		Name:          existing.Name, // Name cannot be changed
		Description:   existing.Description,
		Source:        existing.Source,
		Value:         existing.Value,
		AlwaysInclude: existing.AlwaysInclude,
		Scopes:        existing.Scopes,
		Enabled:       existing.Enabled,
		Required:      existing.Required,
		ConfigData:    existing.ConfigData,
	}

	if req.Description != nil {
		input.Description = *req.Description
	}
	if req.Source != nil {
		input.Source = *req.Source
	}
	if req.Value != nil {
		input.Value = *req.Value
	}
	if req.AlwaysInclude != nil {
		input.AlwaysInclude = *req.AlwaysInclude
	}
	if req.Scopes != nil {
		input.Scopes = req.Scopes
	}
	if req.Enabled != nil {
		input.Enabled = *req.Enabled
	}
	if req.Required != nil {
		input.Required = *req.Required
	}
	if req.ConfigData != nil {
		input.ConfigData = req.ConfigData
	}

	// JSON SCHEMA VALIDATION (Fase 6.5)
	if err := claims.ValidateClaimConfig(input.Source, input.ConfigData); err != nil {
		log.Warn("json schema claim config rejected", logger.Err(err))
		return nil, fmt.Errorf("configuración malformada para resolver '%s': %w", input.Source, err)
	}

	claim, err := s.cp.UpdateCustomClaim(ctx, tenantSlug, claimID, input)
	if err != nil {
		log.Error("failed to update custom claim", logger.Err(err))
		return nil, err
	}

	log.Info("custom claim updated", logger.String("claim_id", claimID))
	resp := toClaimResponse(*claim)
	return &resp, nil
}

func (s *claimsService) DeleteCustomClaim(ctx context.Context, tenantSlug, claimID string) error {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("DeleteCustomClaim"),
		logger.TenantSlug(tenantSlug),
	)

	if err := s.cp.DeleteCustomClaim(ctx, tenantSlug, claimID); err != nil {
		log.Error("failed to delete custom claim", logger.Err(err))
		return err
	}

	log.Info("custom claim deleted", logger.String("claim_id", claimID))
	return nil
}

func (s *claimsService) ToggleStandardClaim(ctx context.Context, tenantSlug, claimName string, enabled bool) error {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("ToggleStandardClaim"),
		logger.TenantSlug(tenantSlug),
	)

	if err := s.cp.ToggleStandardClaim(ctx, tenantSlug, claimName, enabled); err != nil {
		log.Error("failed to toggle standard claim", logger.Err(err))
		return err
	}

	log.Info("standard claim toggled", logger.String("claim_name", claimName), logger.Bool("enabled", enabled))
	return nil
}

func (s *claimsService) GetSettings(ctx context.Context, tenantSlug string) (*dto.ClaimsSettingsResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("GetSettings"),
		logger.TenantSlug(tenantSlug),
	)

	settings, err := s.cp.GetClaimsSettings(ctx, tenantSlug)
	if err != nil {
		log.Error("failed to get claims settings", logger.Err(err))
		return nil, err
	}

	return &dto.ClaimsSettingsResponse{
		IncludeInAccessToken: settings.IncludeInAccessToken,
		UseNamespacedClaims:  settings.UseNamespacedClaims,
		NamespacePrefix:      settings.NamespacePrefix,
	}, nil
}

func (s *claimsService) UpdateSettings(ctx context.Context, tenantSlug string, req dto.ClaimsSettingsUpdateRequest) (*dto.ClaimsSettingsResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("UpdateSettings"),
		logger.TenantSlug(tenantSlug),
	)

	input := repository.ClaimsSettingsInput{
		IncludeInAccessToken: req.IncludeInAccessToken,
		UseNamespacedClaims:  req.UseNamespacedClaims,
		NamespacePrefix:      req.NamespacePrefix,
	}

	settings, err := s.cp.UpdateClaimsSettings(ctx, tenantSlug, input)
	if err != nil {
		log.Error("failed to update claims settings", logger.Err(err))
		return nil, err
	}

	log.Info("claims settings updated")
	return &dto.ClaimsSettingsResponse{
		IncludeInAccessToken: settings.IncludeInAccessToken,
		UseNamespacedClaims:  settings.UseNamespacedClaims,
		NamespacePrefix:      settings.NamespacePrefix,
	}, nil
}

func (s *claimsService) GetScopeMappings(ctx context.Context, tenantSlug string) ([]dto.ScopeMappingResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("GetScopeMappings"),
		logger.TenantSlug(tenantSlug),
	)

	mappings, err := s.cp.GetScopeMappings(ctx, tenantSlug)
	if err != nil {
		log.Error("failed to get scope mappings", logger.Err(err))
		return nil, err
	}

	result := make([]dto.ScopeMappingResponse, len(mappings))
	for i, m := range mappings {
		result[i] = dto.ScopeMappingResponse{
			Scope:  m.Scope,
			Claims: m.Claims,
		}
	}
	return result, nil
}

func toClaimResponse(c repository.ClaimDefinition) dto.ClaimResponse {
	resp := dto.ClaimResponse{
		ID:            c.ID,
		Name:          c.Name,
		Description:   c.Description,
		Source:        c.Source,
		Value:         c.Value,
		AlwaysInclude: c.AlwaysInclude,
		Scopes:        c.Scopes,
		Enabled:       c.Enabled,
		System:        c.System,
		Required:      c.Required,
		ConfigData:    c.ConfigData,
	}
	if !c.CreatedAt.IsZero() {
		resp.CreatedAt = c.CreatedAt.Format("2006-01-02T15:04:05Z07:00")
	}
	if !c.UpdatedAt.IsZero() {
		resp.UpdatedAt = c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
	}
	return resp
}

func (s *claimsService) EvaluatePlayground(ctx context.Context, tenantSlug string, req dto.ClaimPlaygroundRequest) (*dto.ClaimPlaygroundResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentClaims),
		logger.Op("EvaluatePlayground"),
	)

	// Validación del guardián del JsonSchema
	if err := claims.ValidateClaimConfig(req.ResolverType, req.ConfigData); err != nil {
		log.Warn("playground schema validation rejected", logger.Err(err))
		return &dto.ClaimPlaygroundResponse{
			Success: false,
			Error:   fmt.Sprintf("Syntax Error (Schema): %v", err),
		}, nil
	}

	// Pseudo-Contexto Omitiendo DB Layer para Testing
	rin := resolver.ResolverInput{
		UserID:      "play_" + tenantSlug,
		TenantID:    tenantSlug,
		Email:       req.MockContext.Email,
		Scopes:      req.MockContext.Scopes,
		Roles:       req.MockContext.Roles,
		Permissions: []string{"test:permission"},
		UserMeta:    req.MockContext.UserMeta,
	}

	var evaluator resolver.Resolver
	switch req.ResolverType {
	case "static":
		evaluator = &resolver.StaticResolver{Value: req.ConfigData["value"]}
	case "user_attribute":
		fld, _ := req.ConfigData["field"].(string)
		evaluator = &resolver.UserAttributeResolver{Field: fld}
	case "expression":
		exprStr, _ := req.ConfigData["expression"].(string)
		celEng, _ := resolver.NewCELEngine()
		prg, err := celEng.Compile(exprStr)
		if err != nil {
			return &dto.ClaimPlaygroundResponse{Success: false, Error: "CEL AST Error: " + err.Error()}, nil
		}
		evaluator = resolver.NewExpressionResolver(prg)
	case "webhook_api":
		tgtURL, _ := req.ConfigData["url"].(string)
		hmap := map[string]string{}
		if headers, ok := req.ConfigData["headers"].(map[string]any); ok {
			for k, v := range headers {
				if vs, ok := v.(string); ok {
					hmap[k] = vs
				}
			}
		}
		var hookErr error
		evaluator, hookErr = resolver.NewWebhookResolver(tgtURL, "playground_secret", 2*time.Second, hmap)
		if hookErr != nil {
			return &dto.ClaimPlaygroundResponse{Success: false, Error: "Webhook Build Error: " + hookErr.Error()}, nil
		}
	default:
		return &dto.ClaimPlaygroundResponse{Success: false, Error: "Unknown resolver_type"}, nil
	}

	// Timeboxing contra el Sandbox
	evalCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	result, err := evaluator.Resolve(evalCtx, rin)
	if err != nil {
		return &dto.ClaimPlaygroundResponse{Success: false, Error: "Ejecución Fallida: " + err.Error()}, nil
	}

	return &dto.ClaimPlaygroundResponse{
		Success: true,
		Result:  result,
	}, nil
}
