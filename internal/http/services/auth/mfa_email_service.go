package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	adaptive "github.com/dropDatabas3/hellojohn/internal/mfa/adaptive"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	security "github.com/dropDatabas3/hellojohn/internal/security"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

var (
	ErrMFAEmailNotAvailable        = errors.New("email mfa not available")
	ErrMFAEmailRateLimited         = errors.New("email mfa rate limit exceeded")
	ErrMFAEmailInvalidCode         = errors.New("invalid email mfa code")
	ErrMFAEmailProviderUnavailable = errors.New("email provider unavailable")
)

const (
	mfaEmailMaxAttempts       = 5
	mfaEmailRateLimitWindow   = time.Hour
	defaultMFAEmailOTPLength  = 6
	defaultMFAEmailOTPTimeout = 5 * time.Minute
	defaultMFAEmailSubject    = "Your verification code"
)

// MFAEmailService handles Email MFA challenge flow.
type MFAEmailService interface {
	Send(ctx context.Context, tenantSlug string, req SendEmailRequest) (*SendEmailResponse, error)
	Challenge(ctx context.Context, tenantSlug string, req ChallengeEmailRequest) (*ChallengeTOTPResponse, error)
}

// MFAEmailDeps contains dependencies for MFAEmailService.
type MFAEmailDeps struct {
	DAL              store.DataAccessLayer
	Issuer           *jwtx.Issuer
	Email            emailv2.Service
	RefreshTTL       time.Duration
	ClaimsHook       ClaimsHook
	OTPLength        int
	OTPTTL           time.Duration
	RateLimitHourly  int
	Subject          string
	AdaptiveStateTTL time.Duration
	AuditBus         *audit.AuditBus
}

type mfaEmailService struct {
	dal              store.DataAccessLayer
	issuer           *jwtx.Issuer
	email            emailv2.Service
	refreshTTL       time.Duration
	claimsHook       ClaimsHook
	otpLength        int
	otpTTL           time.Duration
	rateLimitHourly  int
	subject          string
	adaptiveStateTTL time.Duration
	auditBus         *audit.AuditBus
}

type mfaEmailCodeSession struct {
	CodeHash  string    `json:"code_hash"`
	Attempts  int       `json:"attempts"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SendEmailRequest describes send Email challenge input.
type SendEmailRequest struct {
	MFAToken string
}

// SendEmailResponse describes send Email challenge response.
type SendEmailResponse struct {
	Sent      bool
	ExpiresIn int64
}

// ChallengeEmailRequest describes Email challenge verification input.
type ChallengeEmailRequest struct {
	MFAToken       string
	Code           string
	RememberDevice bool
}

// NewMFAEmailService creates a new MFAEmailService.
func NewMFAEmailService(d MFAEmailDeps) MFAEmailService {
	otpLength := d.OTPLength
	if otpLength <= 0 || otpLength > 10 {
		otpLength = defaultMFAEmailOTPLength
	}
	otpTTL := d.OTPTTL
	if otpTTL <= 0 {
		otpTTL = defaultMFAEmailOTPTimeout
	}
	rateLimitHourly := d.RateLimitHourly
	if rateLimitHourly <= 0 {
		rateLimitHourly = 5
	}
	subject := strings.TrimSpace(d.Subject)
	if subject == "" {
		subject = defaultMFAEmailSubject
	}
	adaptiveStateTTL := d.AdaptiveStateTTL
	if adaptiveStateTTL <= 0 {
		adaptiveStateTTL = adaptive.DefaultStateTTL
	}
	return &mfaEmailService{
		dal:              d.DAL,
		issuer:           d.Issuer,
		email:            d.Email,
		refreshTTL:       d.RefreshTTL,
		claimsHook:       d.ClaimsHook,
		otpLength:        otpLength,
		otpTTL:           otpTTL,
		rateLimitHourly:  rateLimitHourly,
		subject:          subject,
		adaptiveStateTTL: adaptiveStateTTL,
		auditBus:         d.AuditBus,
	}
}

func (s *mfaEmailService) Send(ctx context.Context, tenantSlug string, req SendEmailRequest) (*SendEmailResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.email.send"))

	if strings.TrimSpace(req.MFAToken) == "" {
		return nil, ErrMFAMissingFields
	}
	if s.email == nil {
		return nil, ErrMFAEmailProviderUnavailable
	}

	tda, cacheRepo, _, challenge, err := resolveMFAChallengeFromToken(ctx, s.dal, tenantSlug, req.MFAToken)
	if err != nil {
		return nil, err
	}

	user, err := tda.Users().GetByID(ctx, challenge.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMFAEmailNotAvailable
		}
		log.Error("failed to load user for email challenge", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}
	email := strings.TrimSpace(user.Email)
	if email == "" || !user.EmailVerified {
		return nil, ErrMFAEmailNotAvailable
	}

	if err := checkMFAEmailRateLimit(ctx, cacheRepo, challenge.TenantID, challenge.UserID, s.rateLimitHourly); err != nil {
		if errors.Is(err, ErrMFAEmailRateLimited) {
			return nil, err
		}
		log.Error("failed to check email mfa rate limit", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	code, err := security.GenerateOTP(s.otpLength)
	if err != nil {
		log.Error("failed to generate email otp", logger.Err(err))
		return nil, ErrMFACryptoFailed
	}

	otpSession := mfaEmailCodeSession{
		CodeHash:  tokens.SHA256Base64URL(code),
		Attempts:  0,
		TenantID:  challenge.TenantID,
		UserID:    challenge.UserID,
		ClientID:  challenge.ClientID,
		ExpiresAt: time.Now().UTC().Add(s.otpTTL),
	}
	otpPayload, err := json.Marshal(otpSession)
	if err != nil {
		log.Error("failed to marshal email otp session", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	otpKey := mfaEmailCodeKey(strings.TrimSpace(req.MFAToken))
	if err := cacheRepo.Set(ctx, otpKey, string(otpPayload), s.otpTTL); err != nil {
		log.Error("failed to cache email otp session", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	sender, err := s.email.GetSender(ctx, tenantSlug)
	if err != nil {
		_ = cacheRepo.Delete(ctx, otpKey)
		log.Warn("failed to resolve email sender", logger.Err(err))
		return nil, ErrMFAEmailProviderUnavailable
	}

	ttlMinutes := int(s.otpTTL.Minutes())
	if ttlMinutes <= 0 {
		ttlMinutes = 1
	}
	htmlBody := fmt.Sprintf("<p>Your HelloJohn verification code is:</p><h2>%s</h2><p>It expires in %d minutes.</p>", code, ttlMinutes)
	textBody := fmt.Sprintf("Your HelloJohn verification code is: %s (expires in %d minutes).", code, ttlMinutes)
	if err := sender.Send(email, s.subject, htmlBody, textBody); err != nil {
		_ = cacheRepo.Delete(ctx, otpKey)
		log.Warn("email sender failed for mfa", logger.Err(err))
		return nil, ErrMFAEmailProviderUnavailable
	}

	log.Info("email otp sent",
		logger.TenantID(challenge.TenantID),
		logger.UserID(challenge.UserID),
	)

	return &SendEmailResponse{
		Sent:      true,
		ExpiresIn: int64(s.otpTTL.Seconds()),
	}, nil
}

func (s *mfaEmailService) Challenge(ctx context.Context, tenantSlug string, req ChallengeEmailRequest) (*ChallengeTOTPResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.email.challenge"))

	if strings.TrimSpace(req.MFAToken) == "" || strings.TrimSpace(req.Code) == "" {
		return nil, ErrMFAMissingFields
	}

	tda, cacheRepo, challengeKey, challenge, err := resolveMFAChallengeFromToken(ctx, s.dal, tenantSlug, req.MFAToken)
	if err != nil {
		return nil, err
	}

	otpKey := mfaEmailCodeKey(strings.TrimSpace(req.MFAToken))
	otpPayload, err := cacheRepo.Get(ctx, otpKey)
	if err != nil {
		if cache.IsNotFound(err) {
			return nil, ErrMFAEmailInvalidCode
		}
		log.Error("failed to load email otp session", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	var otpSession mfaEmailCodeSession
	if err := json.Unmarshal([]byte(otpPayload), &otpSession); err != nil {
		log.Warn("invalid email otp cache payload", logger.Err(err))
		_ = cacheRepo.Delete(ctx, otpKey)
		return nil, ErrMFAEmailInvalidCode
	}
	if time.Now().UTC().After(otpSession.ExpiresAt) {
		_ = cacheRepo.Delete(ctx, otpKey)
		return nil, ErrMFAEmailInvalidCode
	}

	incomingHash := tokens.SHA256Base64URL(strings.TrimSpace(req.Code))
	if subtle.ConstantTimeCompare([]byte(otpSession.CodeHash), []byte(incomingHash)) != 1 {
		otpSession.Attempts++
		if otpSession.Attempts >= mfaEmailMaxAttempts {
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
		return nil, ErrMFAEmailInvalidCode
	}

	if err := cacheRepo.Delete(ctx, otpKey); err != nil {
		log.Warn("failed to delete email otp cache", logger.Err(err))
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
				WithMeta("method", "mfa_email").
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

func mfaEmailCodeKey(mfaToken string) string {
	return "mfa:email:code:" + mfaToken
}

func checkMFAEmailRateLimit(ctx context.Context, cacheRepo cache.Client, tenantID, userID string, limit int) error {
	key := fmt.Sprintf("rl:mfa:email:%s:%s", tenantID, userID)
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
		return ErrMFAEmailRateLimited
	}
	return cacheRepo.Set(ctx, key, strconv.Itoa(count+1), mfaEmailRateLimitWindow)
}
