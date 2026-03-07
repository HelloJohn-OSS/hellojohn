package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

const defaultMFAPreferredFactorField = "mfa_preferred_factor"

var (
	ErrMFAFactorInvalid      = errors.New("invalid mfa factor")
	ErrMFAFactorNotAvailable = errors.New("mfa factor not available for user")
)

const (
	mfaFactorTOTP  = "totp"
	mfaFactorSMS   = "sms"
	mfaFactorEmail = "email"
)

// MFAFactorService handles available factors and preferred factor persistence.
type MFAFactorService interface {
	GetFactors(ctx context.Context, tenantSlug, userID string) (*MFAFactorResult, error)
	UpdatePreferredFactor(ctx context.Context, tenantSlug, userID, factor string) (*MFAFactorResult, error)
}

// MFAFactorDeps contains dependencies for MFAFactorService.
type MFAFactorDeps struct {
	DAL                  store.DataAccessLayer
	PhoneField           string
	PreferredFactorField string
	SMSGlobalAvailable   bool
}

// MFAFactorResult contains current factors and preference.
type MFAFactorResult struct {
	AvailableFactors []string
	PreferredFactor  string
	Updated          bool
}

type mfaFactorService struct {
	dal                  store.DataAccessLayer
	phoneField           string
	preferredFactorField string
	smsGlobalAvailable   bool
}

// NewMFAFactorService creates a new MFAFactorService.
func NewMFAFactorService(d MFAFactorDeps) MFAFactorService {
	phoneField := strings.TrimSpace(d.PhoneField)
	if phoneField == "" {
		phoneField = "phone"
	}
	preferredField := strings.TrimSpace(d.PreferredFactorField)
	if preferredField == "" {
		preferredField = defaultMFAPreferredFactorField
	}
	return &mfaFactorService{
		dal:                  d.DAL,
		phoneField:           phoneField,
		preferredFactorField: preferredField,
		smsGlobalAvailable:   d.SMSGlobalAvailable,
	}
}

func (s *mfaFactorService) GetFactors(ctx context.Context, tenantSlug, userID string) (*MFAFactorResult, error) {
	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, ErrMFATenantMismatch
	}
	user, err := tda.Users().GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMFAUserNotFound
		}
		return nil, ErrMFAStoreFailed
	}

	factors, preferred, _, err := collectAvailableMFAFactors(ctx, tda, user, s.phoneField, s.preferredFactorField, s.smsGlobalAvailable)
	if err != nil {
		return nil, err
	}
	return &MFAFactorResult{
		AvailableFactors: factors,
		PreferredFactor:  preferred,
	}, nil
}

func (s *mfaFactorService) UpdatePreferredFactor(ctx context.Context, tenantSlug, userID, factor string) (*MFAFactorResult, error) {
	factor = normalizeMFAFactor(factor)
	if !isValidMFAFactor(factor) {
		return nil, ErrMFAFactorInvalid
	}

	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, ErrMFATenantMismatch
	}
	user, err := tda.Users().GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMFAUserNotFound
		}
		return nil, ErrMFAStoreFailed
	}

	factors, _, _, err := collectAvailableMFAFactors(ctx, tda, user, s.phoneField, s.preferredFactorField, s.smsGlobalAvailable)
	if err != nil {
		return nil, err
	}
	if !containsFactor(factors, factor) {
		return nil, ErrMFAFactorNotAvailable
	}

	if err := tda.Users().Update(ctx, userID, repository.UpdateUserInput{
		CustomFields: map[string]any{
			s.preferredFactorField: factor,
		},
	}); err != nil {
		return nil, ErrMFAStoreFailed
	}

	return &MFAFactorResult{
		AvailableFactors: factors,
		PreferredFactor:  factor,
		Updated:          true,
	}, nil
}

func collectAvailableMFAFactors(ctx context.Context, tda store.TenantDataAccess, user *repository.User, phoneField, preferredField string, smsGlobalAvailable bool) ([]string, string, bool, error) {
	factors := make([]string, 0, 3)

	hasConfirmedTOTP := false
	if mfaRepo := tda.MFA(); mfaRepo != nil {
		mfaCfg, err := mfaRepo.GetTOTP(ctx, user.ID)
		if err == nil && mfaCfg != nil && mfaCfg.ConfirmedAt != nil {
			hasConfirmedTOTP = true
			factors = append(factors, mfaFactorTOTP)
		} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return nil, "", false, ErrMFAStoreFailed
		}
	}

	if isValidE164(resolveSMSPhone(user.CustomFields, phoneField)) && isSMSEnabledForTenant(tda.Settings(), smsGlobalAvailable) {
		factors = append(factors, mfaFactorSMS)
	}
	if strings.TrimSpace(user.Email) != "" && user.EmailVerified {
		factors = append(factors, mfaFactorEmail)
	}

	preferred := resolvePreferredFactor(user.CustomFields, preferredField, factors)
	if preferred == "" {
		preferred = fallbackPreferredFactor(factors)
	}
	return factors, preferred, hasConfirmedTOTP, nil
}

func isSMSEnabledForTenant(settings *repository.TenantSettings, smsGlobalAvailable bool) bool {
	if settings == nil || settings.MFA == nil || settings.MFA.SMS == nil || strings.TrimSpace(settings.MFA.SMS.Provider) == "" {
		return smsGlobalAvailable
	}
	return tenantSMSConfigReady(settings.MFA.SMS)
}

func tenantSMSConfigReady(cfg *repository.TenantSMSConfig) bool {
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

func resolvePreferredFactor(customFields map[string]any, preferredField string, available []string) string {
	if len(customFields) == 0 {
		return ""
	}
	raw, ok := customFields[preferredField]
	if !ok || raw == nil {
		return ""
	}
	value, ok := raw.(string)
	if !ok {
		return ""
	}
	value = normalizeMFAFactor(value)
	if !containsFactor(available, value) {
		return ""
	}
	return value
}

func normalizeMFAFactor(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func isValidMFAFactor(v string) bool {
	switch normalizeMFAFactor(v) {
	case mfaFactorTOTP, mfaFactorSMS, mfaFactorEmail:
		return true
	default:
		return false
	}
}

func containsFactor(factors []string, factor string) bool {
	for _, f := range factors {
		if f == factor {
			return true
		}
	}
	return false
}

func fallbackPreferredFactor(available []string) string {
	order := []string{mfaFactorTOTP, mfaFactorSMS, mfaFactorEmail}
	for _, candidate := range order {
		if containsFactor(available, candidate) {
			return candidate
		}
	}
	return ""
}
