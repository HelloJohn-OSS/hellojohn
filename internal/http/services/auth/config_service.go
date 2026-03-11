package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	bot "github.com/dropDatabas3/hellojohn/internal/http/services/bot"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"github.com/dropDatabas3/hellojohn/internal/passwordpolicy"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"go.uber.org/zap"
)

// ConfigService defines operations for retrieving auth configuration.
type ConfigService interface {
	GetConfig(ctx context.Context, clientID string) (*dto.ConfigResult, error)
	GetPasswordPolicy(ctx context.Context, tenantID string) (*dto.PasswordPolicyResult, error)
}

// ConfigDeps contains dependencies for the config service.
type ConfigDeps struct {
	DAL                        store.DataAccessLayer
	DataRoot                   string // Path to data root for logo file reading
	BotProtection              bot.BotProtectionService
	PasswordPolicyGlobalTenant string
	PasswordPolicyEnv          *repository.SecurityPolicy
}

type configService struct {
	deps ConfigDeps
}

// NewConfigService creates a new ConfigService.
func NewConfigService(deps ConfigDeps) ConfigService {
	if deps.DataRoot == "" {
		deps.DataRoot = "./data/hellojohn"
	}
	return &configService{deps: deps}
}

// Config errors
var (
	ErrConfigClientNotFound = fmt.Errorf("client not found")
	ErrConfigTenantNotFound = fmt.Errorf("tenant not found")
)

// GetConfig returns the auth config for the given client_id.
// If clientID is empty, returns a generic admin config.
func (s *configService) GetConfig(ctx context.Context, clientID string) (*dto.ConfigResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.config"),
		logger.Op("GetConfig"),
	)

	// If no client_id, return admin fallback config
	if clientID == "" {
		log.Debug("no client_id provided, returning admin config")
		return &dto.ConfigResult{
			TenantName:      "HelloJohn Admin",
			PasswordEnabled: true,
		}, nil
	}

	// Find client - iterate tenants to find the one owning this client
	client, tenant, err := s.resolveClientAndTenant(ctx, clientID, log)
	if err != nil {
		return nil, err
	}

	// Build response
	result := &dto.ConfigResult{
		TenantName:      tenant.Name,
		TenantSlug:      tenant.Slug,
		ClientName:      client.Name,
		SocialProviders: filterSocialProviders(client.Providers),
		PasswordEnabled: true, // Default
	}

	// Check if password is in providers
	if len(client.Providers) > 0 {
		result.PasswordEnabled = helpers.IsPasswordProviderAllowed(client.Providers)
	}

	// Email verification config from client
	result.RequireEmailVerification = client.RequireEmailVerification
	result.ResetPasswordURL = client.ResetPasswordURL
	result.VerifyEmailURL = client.VerifyEmailURL

	// Logo resolution
	if tenant.Settings.LogoURL != "" && strings.HasPrefix(tenant.Settings.LogoURL, "http") {
		result.LogoURL = tenant.Settings.LogoURL
	} else {
		// Try to load logo from FS
		logoURL := s.resolveLogoFromFS(tenant.Slug)
		if logoURL != "" {
			result.LogoURL = logoURL
		}
	}

	// Primary color from tenant settings
	if tenant.Settings.BrandColor != "" {
		result.PrimaryColor = tenant.Settings.BrandColor
	}

	// Features
	result.Features = map[string]bool{
		"smtp_enabled":               tenant.Settings.SMTP != nil,
		"social_login_enabled":       tenant.Settings.SocialLoginEnabled,
		"mfa_enabled":                tenant.Settings.MFAEnabled,
		"require_email_verification": result.RequireEmailVerification,
	}

	// Bot protection config (public fields only — never expose secret key)
	if s.deps.BotProtection != nil {
		if botCfg, botErr := s.deps.BotProtection.ResolveConfig(ctx, tenant.Slug); botErr == nil && botCfg.Enabled {
			result.BotProtection = &dto.BotProtectionPublicConfig{
				Enabled:              true,
				Provider:             botCfg.Provider,
				SiteKey:              botCfg.SiteKey,
				ProtectLogin:         botCfg.ProtectLogin,
				ProtectRegistration:  botCfg.ProtectRegistration,
				ProtectPasswordReset: botCfg.ProtectPasswordReset,
				Appearance:           botCfg.Appearance,
				Theme:                botCfg.Theme,
			}
		}
	}

	// Custom fields from tenant settings
	for _, uf := range tenant.Settings.UserFields {
		label := uf.Description
		if label == "" {
			label = uf.Name // Fallback
		}
		result.CustomFields = append(result.CustomFields, dto.CustomFieldSchema{
			Name:     uf.Name,
			Type:     uf.Type,
			Label:    label,
			Required: uf.Required,
		})
	}

	log.Info("config resolved",
		logger.TenantSlug(tenant.Slug),
		zap.String("client_id", clientID),
	)

	return result, nil
}

// resolveClientAndTenant resolves client and its tenant from DAL.
func (s *configService) resolveClientAndTenant(ctx context.Context, clientID string, log *zap.Logger) (*repository.Client, *repository.Tenant, error) {
	// Get list of tenants from ConfigAccess (control plane)
	tenants, err := s.deps.DAL.ConfigAccess().Tenants().List(ctx)
	if err != nil {
		log.Debug("failed to list tenants", logger.Err(err))
		return nil, nil, ErrConfigClientNotFound
	}

	// Search for the client in each tenant
	for _, t := range tenants {
		tda, err := s.deps.DAL.ForTenant(ctx, t.Slug)
		if err != nil {
			continue
		}

		client, err := tda.Clients().Get(ctx, clientID)
		if err != nil || client == nil {
			continue
		}

		// Found the client!
		return client, &t, nil
	}

	log.Debug("client not found in any tenant", zap.String("client_id", clientID))
	return nil, nil, ErrConfigClientNotFound
}

// resolveLogoFromFS reads logo.png from tenant FS folder and returns base64 data URL.
func (s *configService) resolveLogoFromFS(tenantSlug string) string {
	logoPath := filepath.Join(s.deps.DataRoot, "tenants", tenantSlug, "logo.png")
	data, err := os.ReadFile(logoPath)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
}

// filterSocialProviders returns only social providers (excludes "password").
func filterSocialProviders(providers []string) []string {
	var social []string
	for _, p := range providers {
		if !strings.EqualFold(p, "password") {
			social = append(social, p)
		}
	}
	return social
}

// GetPasswordPolicy returns effective password policy for a tenant.
// If tenantID is empty, returns secure defaults.
func (s *configService) GetPasswordPolicy(ctx context.Context, tenantID string) (*dto.PasswordPolicyResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	var (
		resolved passwordpolicy.ResolvedPolicy
		err      error
	)

	if tenantID != "" {
		resolved, err = passwordpolicy.ResolveForTenant(
			ctx,
			s.deps.DAL,
			tenantID,
			s.deps.PasswordPolicyGlobalTenant,
			s.deps.PasswordPolicyEnv,
		)
		if err != nil {
			return nil, ErrConfigTenantNotFound
		}
	} else {
		resolved = passwordpolicy.ResolveForCloud(
			ctx,
			s.deps.DAL,
			s.deps.PasswordPolicyGlobalTenant,
			s.deps.PasswordPolicyEnv,
		)
	}

	result := &dto.PasswordPolicyResult{
		Configured:       resolved.Configured,
		Source:           string(resolved.Source),
		TenantID:         resolved.TenantID,
		MinLength:        resolved.Policy.PasswordMinLength,
		MaxLength:        passwordpolicy.DefaultMaxLength,
		RequireUppercase: resolved.Policy.RequireUppercase,
		RequireLowercase: resolved.Policy.RequireLowercase,
		RequireNumbers:   resolved.Policy.RequireNumbers,
		RequireSymbols:   resolved.Policy.RequireSpecialChars,
		MaxHistory:       resolved.Policy.MaxHistory,
		BreachDetection:  resolved.Policy.BreachDetection,
		CommonPassword:   true,
		PersonalInfo:     true,
	}

	if result.MinLength <= 0 {
		result.MinLength = passwordpolicy.DefaultMinLength
	}
	return result, nil
}
