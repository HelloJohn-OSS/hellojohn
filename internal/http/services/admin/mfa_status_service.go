package admin

import (
	"context"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	adaptive "github.com/dropDatabas3/hellojohn/internal/mfa/adaptive"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// MFAStatusService returns tenant MFA status for admin usage.
type MFAStatusService interface {
	GetStatus(ctx context.Context, tenantSlug string) (*dto.MFAStatusResponse, error)
}

// MFAStatusDeps contains dependencies for MFA status service.
type MFAStatusDeps struct {
	DAL                      store.DataAccessLayer
	SMSGlobalProvider        string
	AdaptiveEnabled          bool
	AdaptiveRules            []string
	AdaptiveFailureThreshold int
}

type mfaStatusService struct {
	deps MFAStatusDeps
}

// NewMFAStatusService builds MFA status service.
func NewMFAStatusService(deps MFAStatusDeps) MFAStatusService {
	return &mfaStatusService{deps: deps}
}

func (s *mfaStatusService) GetStatus(ctx context.Context, tenantSlug string) (*dto.MFAStatusResponse, error) {
	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}

	settings := tda.Settings()

	mfaEnabled := settings != nil && settings.MFAEnabled
	mfaRequired := false
	smtpConfigured := false
	if settings != nil {
		if settings.Security != nil {
			mfaRequired = settings.Security.MFARequired
		}
		smtpConfigured = settings.SMTP != nil && strings.TrimSpace(settings.SMTP.Host) != ""
	}

	smsProvider := "none"
	smsProviderName := ""
	if settings != nil && settings.MFA != nil && settings.MFA.SMS != nil && strings.TrimSpace(settings.MFA.SMS.Provider) != "" {
		smsProvider = "tenant"
		smsProviderName = strings.ToLower(strings.TrimSpace(settings.MFA.SMS.Provider))
	} else if strings.TrimSpace(s.deps.SMSGlobalProvider) != "" {
		smsProvider = "global"
		smsProviderName = strings.ToLower(strings.TrimSpace(s.deps.SMSGlobalProvider))
	}

	smsAvailable := false
	if smsProvider == "tenant" && settings != nil && settings.MFA != nil && settings.MFA.SMS != nil {
		smsAvailable = tenantSMSHasCredentials(settings.MFA.SMS)
	} else if smsProvider == "global" {
		smsAvailable = true
	}

	adaptiveCfg := adaptive.Config{
		Enabled:          s.deps.AdaptiveEnabled,
		Rules:            s.deps.AdaptiveRules,
		FailureThreshold: s.deps.AdaptiveFailureThreshold,
	}.Normalize()
	adaptiveEnabled := adaptiveCfg.Enabled
	adaptiveRules := adaptiveCfg.Rules
	adaptiveThreshold := adaptiveCfg.FailureThreshold
	if settings != nil && settings.MFA != nil && settings.MFA.Adaptive != nil {
		if settings.MFA.Adaptive.Enabled != nil {
			adaptiveEnabled = *settings.MFA.Adaptive.Enabled
		}
		if len(settings.MFA.Adaptive.Rules) > 0 {
			adaptiveRules = normalizeRuleNames(settings.MFA.Adaptive.Rules)
		}
		if settings.MFA.Adaptive.FailureThreshold > 0 {
			adaptiveThreshold = settings.MFA.Adaptive.FailureThreshold
		}
	}

	return &dto.MFAStatusResponse{
		MFAEnabled:  mfaEnabled,
		MFARequired: mfaRequired,
		Methods: dto.MFAMethods{
			TOTP: dto.MFATOTPStatus{
				Available: true,
			},
			SMS: dto.MFASMSStatus{
				Available:    smsAvailable,
				Provider:     smsProvider,
				ProviderName: smsProviderName,
			},
			Email: dto.MFAEmailStatus{
				Available:      smtpConfigured,
				SMTPConfigured: smtpConfigured,
			},
		},
		Adaptive: dto.MFAAdaptive{
			Enabled:          adaptiveEnabled,
			Rules:            adaptiveRules,
			FailureThreshold: adaptiveThreshold,
		},
	}, nil
}
