package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	adaptive "github.com/dropDatabas3/hellojohn/internal/mfa/adaptive"
	smspkg "github.com/dropDatabas3/hellojohn/internal/mfa/sms"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	security "github.com/dropDatabas3/hellojohn/internal/security"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

var (
	ErrMFASMSNotAvailable        = errors.New("sms not available")
	ErrMFASMSRateLimited         = errors.New("sms rate limit exceeded")
	ErrMFASMSInvalidCode         = errors.New("invalid sms code")
	ErrMFASMSProviderUnavailable = errors.New("sms provider unavailable")
)

const (
	mfaSMSMaxAttempts       = 5
	mfaSMSRateLimitWindow   = time.Hour
	defaultMFASMSOTPLength  = 6
	defaultMFASMSOTPTimeout = 5 * time.Minute
)

var e164Regexp = regexp.MustCompile(`^\+[1-9]\d{7,14}$`)

// MFASMSService handles SMS MFA challenge flow.
type MFASMSService interface {
	Send(ctx context.Context, tenantSlug string, req SendSMSRequest) (*SendSMSResponse, error)
	Challenge(ctx context.Context, tenantSlug string, req ChallengeSMSRequest) (*ChallengeTOTPResponse, error)
}

// MFASMSDeps contains dependencies for MFASMSService.
type MFASMSDeps struct {
	DAL              store.DataAccessLayer
	Issuer           *jwtx.Issuer
	RefreshTTL       time.Duration
	ClaimsHook       ClaimsHook
	Provider         smspkg.SMSProvider
	PhoneField       string
	OTPLength        int
	OTPTTL           time.Duration
	RateLimitHourly  int
	AdaptiveStateTTL time.Duration
	AuditBus         *audit.AuditBus
}

type mfaSMSService struct {
	dal              store.DataAccessLayer
	issuer           *jwtx.Issuer
	refreshTTL       time.Duration
	claimsHook       ClaimsHook
	provider         smspkg.SMSProvider
	phoneField       string
	otpLength        int
	otpTTL           time.Duration
	rateLimitHourly  int
	adaptiveStateTTL time.Duration
	auditBus         *audit.AuditBus
}

type mfaSMSCodeSession struct {
	CodeHash  string    `json:"code_hash"`
	Attempts  int       `json:"attempts"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SendSMSRequest describes send SMS challenge input.
type SendSMSRequest struct {
	MFAToken string
}

// SendSMSResponse describes send SMS challenge response.
type SendSMSResponse struct {
	Sent      bool
	ExpiresIn int64
}

// ChallengeSMSRequest describes SMS challenge verification input.
type ChallengeSMSRequest struct {
	MFAToken       string
	Code           string
	RememberDevice bool
}

// NewMFASMSService creates a new MFASMSService.
func NewMFASMSService(d MFASMSDeps) MFASMSService {
	otpLength := d.OTPLength
	if otpLength <= 0 || otpLength > 10 {
		otpLength = defaultMFASMSOTPLength
	}
	otpTTL := d.OTPTTL
	if otpTTL <= 0 {
		otpTTL = defaultMFASMSOTPTimeout
	}
	phoneField := strings.TrimSpace(d.PhoneField)
	if phoneField == "" {
		phoneField = "phone"
	}
	rateLimitHourly := d.RateLimitHourly
	if rateLimitHourly <= 0 {
		rateLimitHourly = 5
	}
	adaptiveStateTTL := d.AdaptiveStateTTL
	if adaptiveStateTTL <= 0 {
		adaptiveStateTTL = adaptive.DefaultStateTTL
	}
	return &mfaSMSService{
		dal:              d.DAL,
		issuer:           d.Issuer,
		refreshTTL:       d.RefreshTTL,
		claimsHook:       d.ClaimsHook,
		provider:         d.Provider,
		phoneField:       phoneField,
		otpLength:        otpLength,
		otpTTL:           otpTTL,
		rateLimitHourly:  rateLimitHourly,
		adaptiveStateTTL: adaptiveStateTTL,
		auditBus:         d.AuditBus,
	}
}

func (s *mfaSMSService) Send(ctx context.Context, tenantSlug string, req SendSMSRequest) (*SendSMSResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.sms.send"))

	if strings.TrimSpace(req.MFAToken) == "" {
		return nil, ErrMFAMissingFields
	}

	tda, cacheRepo, _, challenge, err := resolveMFAChallengeFromToken(ctx, s.dal, tenantSlug, req.MFAToken)
	if err != nil {
		return nil, err
	}
	provider := s.resolveProvider(tda)
	if provider == nil {
		return nil, ErrMFASMSProviderUnavailable
	}

	user, err := tda.Users().GetByID(ctx, challenge.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMFASMSNotAvailable
		}
		log.Error("failed to load user for sms challenge", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	phone := resolveSMSPhone(user.CustomFields, s.phoneField)
	if !isValidE164(phone) {
		return nil, ErrMFASMSNotAvailable
	}

	if err := checkSMSRateLimit(ctx, cacheRepo, challenge.TenantID, challenge.UserID, s.rateLimitHourly); err != nil {
		if errors.Is(err, ErrMFASMSRateLimited) {
			return nil, err
		}
		log.Error("failed to check sms rate limit", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	code, err := security.GenerateOTP(s.otpLength)
	if err != nil {
		log.Error("failed to generate sms otp", logger.Err(err))
		return nil, ErrMFACryptoFailed
	}

	otpSession := mfaSMSCodeSession{
		CodeHash:  tokens.SHA256Base64URL(code),
		Attempts:  0,
		TenantID:  challenge.TenantID,
		UserID:    challenge.UserID,
		ClientID:  challenge.ClientID,
		ExpiresAt: time.Now().UTC().Add(s.otpTTL),
	}
	otpPayload, err := json.Marshal(otpSession)
	if err != nil {
		log.Error("failed to marshal sms otp session", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	otpKey := mfaSMSCodeKey(strings.TrimSpace(req.MFAToken))
	if err := cacheRepo.Set(ctx, otpKey, string(otpPayload), s.otpTTL); err != nil {
		log.Error("failed to cache sms otp session", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	ttlMinutes := int(s.otpTTL.Minutes())
	if ttlMinutes <= 0 {
		ttlMinutes = 1
	}
	body := fmt.Sprintf("Your HelloJohn verification code is %s. It expires in %d minutes.", code, ttlMinutes)
	if err := provider.Send(ctx, phone, body); err != nil {
		_ = cacheRepo.Delete(ctx, otpKey)
		log.Warn("sms provider send failed", logger.Err(err))
		return nil, ErrMFASMSProviderUnavailable
	}

	log.Info("sms otp sent",
		logger.TenantID(challenge.TenantID),
		logger.UserID(challenge.UserID),
	)

	return &SendSMSResponse{
		Sent:      true,
		ExpiresIn: int64(s.otpTTL.Seconds()),
	}, nil
}

func (s *mfaSMSService) Challenge(ctx context.Context, tenantSlug string, req ChallengeSMSRequest) (*ChallengeTOTPResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.sms.challenge"))

	if strings.TrimSpace(req.MFAToken) == "" || strings.TrimSpace(req.Code) == "" {
		return nil, ErrMFAMissingFields
	}

	tda, cacheRepo, challengeKey, challenge, err := resolveMFAChallengeFromToken(ctx, s.dal, tenantSlug, req.MFAToken)
	if err != nil {
		return nil, err
	}

	otpKey := mfaSMSCodeKey(strings.TrimSpace(req.MFAToken))
	otpPayload, err := cacheRepo.Get(ctx, otpKey)
	if err != nil {
		if cache.IsNotFound(err) {
			return nil, ErrMFASMSInvalidCode
		}
		log.Error("failed to load sms otp session", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	var otpSession mfaSMSCodeSession
	if err := json.Unmarshal([]byte(otpPayload), &otpSession); err != nil {
		log.Warn("invalid sms otp cache payload", logger.Err(err))
		_ = cacheRepo.Delete(ctx, otpKey)
		return nil, ErrMFASMSInvalidCode
	}

	if time.Now().UTC().After(otpSession.ExpiresAt) {
		_ = cacheRepo.Delete(ctx, otpKey)
		return nil, ErrMFASMSInvalidCode
	}

	incomingHash := tokens.SHA256Base64URL(strings.TrimSpace(req.Code))
	if subtle.ConstantTimeCompare([]byte(otpSession.CodeHash), []byte(incomingHash)) != 1 {
		otpSession.Attempts++
		if otpSession.Attempts >= mfaSMSMaxAttempts {
			_ = cacheRepo.Delete(ctx, otpKey)
		} else {
			remaining := time.Until(otpSession.ExpiresAt)
			if remaining <= 0 {
				_ = cacheRepo.Delete(ctx, otpKey)
			} else {
				nextPayload, _ := json.Marshal(otpSession)
				_ = cacheRepo.Set(ctx, otpKey, string(nextPayload), remaining)
			}
		}
		return nil, ErrMFASMSInvalidCode
	}

	if err := cacheRepo.Delete(ctx, otpKey); err != nil {
		log.Warn("failed to delete sms otp cache", logger.Err(err))
	}

	deviceToken := ""
	if req.RememberDevice {
		mfaRepo := tda.MFA()
		if mfaRepo != nil {
			rawDev, err := tokens.GenerateOpaqueToken(32)
			if err != nil {
				log.Warn("failed to generate trusted device token", logger.Err(err))
			} else {
				devHash := tokens.SHA256Base64URL(rawDev)
				expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
				if err := mfaRepo.AddTrustedDevice(ctx, challenge.UserID, devHash, expiresAt); err != nil {
					log.Warn("failed to persist trusted device", logger.Err(err))
				} else {
					deviceToken = rawDev
				}
			}
		}
	}

	accessToken, refreshToken, expiresIn, err := issueMFAChallengeTokens(ctx, s.issuer, tda, challenge, s.refreshTTL, s.claimsHook)
	if err != nil {
		return nil, err
	}

	if err := cacheRepo.Delete(ctx, challengeKey); err != nil {
		log.Warn("failed to delete mfa challenge token", logger.Err(err))
	}
	if err := adaptive.SaveSuccessState(
		ctx,
		cacheRepo,
		challenge.TenantID,
		challenge.UserID,
		mw.GetClientIP(ctx),
		mw.GetUserAgent(ctx),
		s.adaptiveStateTTL,
	); err != nil {
		log.Warn("failed to persist adaptive success state", logger.Err(err))
	}

	if s.auditBus != nil {
		s.auditBus.Emit(
			audit.NewEvent(audit.EventLogin, tda.ID()).
				WithActor(challenge.UserID, audit.ActorUser).
				WithTarget(challenge.UserID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithMeta("method", "mfa_sms").
				WithMeta("client_id", challenge.ClientID),
		)
	}

	return &ChallengeTOTPResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		DeviceToken:  deviceToken,
	}, nil
}

func checkSMSRateLimit(ctx context.Context, cacheRepo cache.Client, tenantID, userID string, limit int) error {
	key := fmt.Sprintf("rl:mfa:sms:%s:%s", tenantID, userID)
	countRaw, err := cacheRepo.Get(ctx, key)
	if err != nil && !cache.IsNotFound(err) {
		return err
	}
	count := 0
	if countRaw != "" {
		if parsed, parseErr := strconv.Atoi(strings.TrimSpace(countRaw)); parseErr == nil {
			count = parsed
		}
	}
	if count >= limit {
		return ErrMFASMSRateLimited
	}
	return cacheRepo.Set(ctx, key, strconv.Itoa(count+1), mfaSMSRateLimitWindow)
}

func mfaSMSCodeKey(mfaToken string) string {
	return "mfa:sms:code:" + mfaToken
}

func resolveSMSPhone(customFields map[string]any, phoneField string) string {
	if len(customFields) == 0 {
		return ""
	}
	candidates := []string{strings.TrimSpace(phoneField)}
	if strings.TrimSpace(phoneField) != "phone_number" {
		candidates = append(candidates, "phone_number")
	}
	if strings.TrimSpace(phoneField) != "phone" {
		candidates = append(candidates, "phone")
	}
	for _, field := range candidates {
		if field == "" {
			continue
		}
		raw, ok := customFields[field]
		if !ok || raw == nil {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func isValidE164(phone string) bool {
	return e164Regexp.MatchString(strings.TrimSpace(phone))
}

// resolveProvider returns tenant-specific provider when configured, otherwise global provider.
func (s *mfaSMSService) resolveProvider(tda store.TenantDataAccess) smspkg.SMSProvider {
	settings := tda.Settings()
	if settings == nil || settings.MFA == nil || settings.MFA.SMS == nil || strings.TrimSpace(settings.MFA.SMS.Provider) == "" {
		return s.provider
	}

	smsCfg := settings.MFA.SMS
	providerName := strings.ToLower(strings.TrimSpace(smsCfg.Provider))
	if !tenantSMSHasCredentialsForRuntime(smsCfg) {
		return nil
	}

	cfg := smspkg.Config{
		Provider: providerName,
		Timeout:  10 * time.Second,
	}

	switch providerName {
	case "twilio":
		sid, err := secretbox.Decrypt(smsCfg.TwilioAccountSIDEnc)
		if err != nil {
			return nil
		}
		token, err := secretbox.Decrypt(smsCfg.TwilioAuthTokenEnc)
		if err != nil {
			return nil
		}
		cfg.TwilioAccountSID = sid
		cfg.TwilioAuthToken = token
		cfg.TwilioFrom = strings.TrimSpace(smsCfg.TwilioFrom)
	case "vonage":
		key, err := secretbox.Decrypt(smsCfg.VonageAPIKeyEnc)
		if err != nil {
			return nil
		}
		secret, err := secretbox.Decrypt(smsCfg.VonageAPISecretEnc)
		if err != nil {
			return nil
		}
		cfg.VonageAPIKey = key
		cfg.VonageAPISecret = secret
		cfg.VonageFrom = strings.TrimSpace(smsCfg.VonageFrom)
	default:
		return nil
	}

	p, err := smspkg.NewProvider(cfg)
	if err != nil {
		return nil
	}
	return p
}

func tenantSMSHasCredentialsForRuntime(cfg *repository.TenantSMSConfig) bool {
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
