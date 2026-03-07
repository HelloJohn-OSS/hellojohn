package admin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	adaptive "github.com/dropDatabas3/hellojohn/internal/mfa/adaptive"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// MFAConfigService manages tenant-level MFA configuration.
type MFAConfigService interface {
	GetConfig(ctx context.Context, tenantSlug string) (*dto.MFAConfigResponse, error)
	UpdateConfig(ctx context.Context, tenantSlug string, req dto.UpdateMFAConfigRequest) (*dto.MFAConfigResponse, error)
}

// MFAConfigDeps contains dependencies for MFAConfigService.
type MFAConfigDeps struct {
	DAL                     store.DataAccessLayer
	GlobalSMSProvider       string
	GlobalTOTPIssuer        string
	GlobalTOTPWindow        int
	GlobalAdaptiveEnabled   bool
	GlobalAdaptiveRules     []string
	GlobalAdaptiveThreshold int
	GlobalAdaptiveStateTTL  time.Duration
}

type mfaConfigService struct {
	deps MFAConfigDeps
}

// NewMFAConfigService creates a new MFAConfigService.
func NewMFAConfigService(deps MFAConfigDeps) MFAConfigService {
	return &mfaConfigService{deps: deps}
}

func (s *mfaConfigService) GetConfig(ctx context.Context, tenantSlug string) (*dto.MFAConfigResponse, error) {
	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}

	settings := tda.Settings()
	var tenantMFA *repository.MFAConfig
	if settings != nil {
		tenantMFA = settings.MFA
	}

	globalAdaptive := adaptive.Config{
		Enabled:          s.deps.GlobalAdaptiveEnabled,
		Rules:            s.deps.GlobalAdaptiveRules,
		FailureThreshold: s.deps.GlobalAdaptiveThreshold,
		StateTTL:         s.deps.GlobalAdaptiveStateTTL,
	}.Normalize()

	totpIssuer := strings.TrimSpace(s.deps.GlobalTOTPIssuer)
	if totpIssuer == "" {
		totpIssuer = "HelloJohn"
	}
	totpIsGlobal := true
	totpWindow := s.deps.GlobalTOTPWindow
	if totpWindow <= 0 {
		totpWindow = 1
	}
	totpWindowIsGlobal := true

	if tenantMFA != nil {
		if strings.TrimSpace(tenantMFA.TOTPIssuer) != "" {
			totpIssuer = strings.TrimSpace(tenantMFA.TOTPIssuer)
			totpIsGlobal = false
		}
		if tenantMFA.TOTPWindow > 0 {
			totpWindow = tenantMFA.TOTPWindow
			totpWindowIsGlobal = false
		}
	}

	smsProvider := "none"
	smsProviderName := ""
	smsHasCredentials := false
	smsFrom := ""
	if tenantMFA != nil && tenantMFA.SMS != nil && strings.TrimSpace(tenantMFA.SMS.Provider) != "" {
		smsProvider = "tenant"
		smsProviderName = strings.ToLower(strings.TrimSpace(tenantMFA.SMS.Provider))
		smsHasCredentials = tenantSMSHasCredentials(tenantMFA.SMS)
		smsFrom = tenantSMSFrom(tenantMFA.SMS)
	} else if strings.TrimSpace(s.deps.GlobalSMSProvider) != "" {
		smsProvider = "global"
		smsProviderName = strings.ToLower(strings.TrimSpace(s.deps.GlobalSMSProvider))
		smsHasCredentials = true
	}

	adaptiveEnabled := globalAdaptive.Enabled
	adaptiveRules := cloneStrings(globalAdaptive.Rules)
	adaptiveThreshold := globalAdaptive.FailureThreshold
	adaptiveStateTTLHours := int(globalAdaptive.StateTTL.Hours())
	adaptiveIsGlobal := true
	if tenantMFA != nil && tenantMFA.Adaptive != nil {
		adaptiveIsGlobal = false
		if tenantMFA.Adaptive.Enabled != nil {
			adaptiveEnabled = *tenantMFA.Adaptive.Enabled
		}
		if len(tenantMFA.Adaptive.Rules) > 0 {
			adaptiveRules = normalizeRuleNames(tenantMFA.Adaptive.Rules)
		}
		if tenantMFA.Adaptive.FailureThreshold > 0 {
			adaptiveThreshold = tenantMFA.Adaptive.FailureThreshold
		}
		if tenantMFA.Adaptive.StateTTLHours > 0 {
			adaptiveStateTTLHours = tenantMFA.Adaptive.StateTTLHours
		}
	}

	return &dto.MFAConfigResponse{
		TOTP: dto.MFATOTPConfig{
			Issuer:         totpIssuer,
			IsGlobal:       totpIsGlobal,
			Window:         totpWindow,
			WindowIsGlobal: totpWindowIsGlobal,
		},
		SMS: dto.MFASMSConfigInfo{
			Provider:       smsProvider,
			ProviderName:   smsProviderName,
			HasCredentials: smsHasCredentials,
			From:           smsFrom,
		},
		Adaptive: dto.MFAAdaptiveConfig{
			Enabled:          adaptiveEnabled,
			IsGlobal:         adaptiveIsGlobal,
			Rules:            adaptiveRules,
			FailureThreshold: adaptiveThreshold,
			StateTTLHours:    adaptiveStateTTLHours,
		},
	}, nil
}

func (s *mfaConfigService) UpdateConfig(ctx context.Context, tenantSlug string, req dto.UpdateMFAConfigRequest) (*dto.MFAConfigResponse, error) {
	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}

	settings := tda.Settings()
	if settings == nil {
		settings = &repository.TenantSettings{}
	}

	if settings.MFA == nil {
		settings.MFA = &repository.MFAConfig{}
	}

	if req.TOTP != nil {
		settings.MFA.TOTPIssuer = strings.TrimSpace(req.TOTP.Issuer)
		if req.TOTP.Window > 0 {
			settings.MFA.TOTPWindow = req.TOTP.Window
		} else {
			settings.MFA.TOTPWindow = 0
		}
	}

	if req.SMS != nil {
		provider := strings.ToLower(strings.TrimSpace(req.SMS.Provider))
		if provider == "" {
			settings.MFA.SMS = nil
		} else {
			if provider != "twilio" && provider != "vonage" {
				return nil, fmt.Errorf("%w: invalid sms provider", repository.ErrInvalidInput)
			}
			if settings.MFA.SMS == nil {
				settings.MFA.SMS = &repository.TenantSMSConfig{}
			}
			sms := settings.MFA.SMS
			sms.Provider = provider

			switch provider {
			case "twilio":
				sms.TwilioFrom = strings.TrimSpace(req.SMS.TwilioFrom)
				if strings.TrimSpace(req.SMS.TwilioAccountSID) != "" {
					sms.TwilioAccountSID = strings.TrimSpace(req.SMS.TwilioAccountSID)
				}
				if strings.TrimSpace(req.SMS.TwilioAuthToken) != "" {
					sms.TwilioAuthToken = strings.TrimSpace(req.SMS.TwilioAuthToken)
				}
				sms.VonageFrom = ""
				sms.VonageAPIKey = ""
				sms.VonageAPISecret = ""
				sms.VonageAPIKeyEnc = ""
				sms.VonageAPISecretEnc = ""
			case "vonage":
				sms.VonageFrom = strings.TrimSpace(req.SMS.VonageFrom)
				if strings.TrimSpace(req.SMS.VonageAPIKey) != "" {
					sms.VonageAPIKey = strings.TrimSpace(req.SMS.VonageAPIKey)
				}
				if strings.TrimSpace(req.SMS.VonageAPISecret) != "" {
					sms.VonageAPISecret = strings.TrimSpace(req.SMS.VonageAPISecret)
				}
				sms.TwilioFrom = ""
				sms.TwilioAccountSID = ""
				sms.TwilioAuthToken = ""
				sms.TwilioAccountSIDEnc = ""
				sms.TwilioAuthTokenEnc = ""
			}
		}
	}

	if req.Adaptive != nil {
		if req.Adaptive.UseGlobal {
			settings.MFA.Adaptive = nil
		} else {
			if settings.MFA.Adaptive == nil {
				settings.MFA.Adaptive = &repository.TenantAdaptiveConfig{}
			}
			enabled := req.Adaptive.Enabled
			settings.MFA.Adaptive.Enabled = &enabled
			if req.Adaptive.Rules != nil {
				settings.MFA.Adaptive.Rules = normalizeRuleNames(req.Adaptive.Rules)
			}
			if req.Adaptive.FailureThreshold > 0 {
				settings.MFA.Adaptive.FailureThreshold = req.Adaptive.FailureThreshold
			}
			if req.Adaptive.StateTTLHours > 0 {
				settings.MFA.Adaptive.StateTTLHours = req.Adaptive.StateTTLHours
			}
		}
	}

	if err := encryptTenantSecrets(settings, ""); err != nil {
		return nil, fmt.Errorf("encrypt tenant mfa settings: %w", err)
	}

	if err := s.deps.DAL.ConfigAccess().Tenants().UpdateSettings(ctx, tda.Slug(), settings); err != nil {
		return nil, err
	}
	s.deps.DAL.InvalidateTenantCache(tda.Slug())

	return s.GetConfig(ctx, tenantSlug)
}

func tenantSMSHasCredentials(cfg *repository.TenantSMSConfig) bool {
	if cfg == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "twilio":
		return strings.TrimSpace(cfg.TwilioAccountSIDEnc) != "" &&
			strings.TrimSpace(cfg.TwilioAuthTokenEnc) != "" &&
			strings.TrimSpace(cfg.TwilioFrom) != ""
	case "vonage":
		return strings.TrimSpace(cfg.VonageAPIKeyEnc) != "" &&
			strings.TrimSpace(cfg.VonageAPISecretEnc) != "" &&
			strings.TrimSpace(cfg.VonageFrom) != ""
	default:
		return false
	}
}

func tenantSMSFrom(cfg *repository.TenantSMSConfig) string {
	if cfg == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "twilio":
		return strings.TrimSpace(cfg.TwilioFrom)
	case "vonage":
		return strings.TrimSpace(cfg.VonageFrom)
	default:
		return ""
	}
}

func normalizeRuleNames(rules []string) []string {
	out := make([]string, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for _, raw := range rules {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
