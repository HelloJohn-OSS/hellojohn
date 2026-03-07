package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dtoa "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"github.com/dropDatabas3/hellojohn/internal/security"
)

// passwordlessService implementa PasswordlessService.
type passwordlessService struct {
	deps PasswordlessDeps
}

// NewPasswordlessService crea un nuevo PasswordlessService.
func NewPasswordlessService(deps PasswordlessDeps) PasswordlessService {
	return &passwordlessService{deps: deps}
}

// ─────────────────────────────────────────────────────────────
// Magic Link
// ─────────────────────────────────────────────────────────────

func (s *passwordlessService) SendMagicLink(ctx context.Context, req MagicLinkRequest) error {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("passwordless.magiclink"))
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if req.Email == "" || req.TenantSlug == "" || req.ClientID == "" {
		return fmt.Errorf("email, tenant_id, and client_id are required")
	}

	tda, err := s.deps.DAL.ForTenant(ctx, req.TenantSlug)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	client, err := tda.Clients().Get(ctx, req.ClientID)
	if err != nil {
		return fmt.Errorf("invalid client_id: %w", err)
	}

	if req.RedirectURI == "" && len(client.RedirectURIs) > 0 {
		req.RedirectURI = client.RedirectURIs[0]
	}

	if req.RedirectURI != "" {
		if !isValidRedirectURI(req.RedirectURI, client.RedirectURIs) {
			return ErrInvalidRedirectURI
		}
	} else {
		return ErrInvalidRedirectURI
	}

	settings := tda.Settings()
	if settings.Passwordless == nil || !settings.Passwordless.MagicLink.Enabled {
		return ErrMagicLinkDisabled
	}
	cfg := settings.Passwordless.MagicLink

	// Generate secure token
	token, err := security.GenerateOpaqueToken(48)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	cacheKey := MagicLinkCacheKey(token)
	session := magicLinkSession{
		Email:       req.Email,
		TenantID:    tda.ID(),
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl == 0 {
		ttl = 15 * time.Minute
	}

	if s.deps.Cache != nil {
		if err := s.deps.Cache.Set(ctx, cacheKey, string(payload), ttl); err != nil {
			return fmt.Errorf("failed to store magic link: %w", err)
		}
	} else {
		return ErrCacheNotConfigured
	}

	log.Info("magic link generated",
		logger.TenantID(req.TenantSlug),
	)

	sender, err := s.deps.Email.GetSender(ctx, req.TenantSlug)
	if err != nil {
		log.Error("failed to get email sender for magic link", logger.Err(err))
		return fmt.Errorf("failed to send magic link email")
	}

	baseURL := strings.TrimRight(strings.TrimSpace(s.deps.BaseURL), "/")
	if baseURL == "" {
		return fmt.Errorf("base url not configured")
	}
	linkURL := fmt.Sprintf("%s/v2/auth/magic-link/consume/%s", baseURL, url.PathEscape(token))

	subject := "Tu enlace de acceso"
	htmlBody := magicLinkHTMLBody(linkURL, cfg.TTLSeconds)
	textBody := magicLinkTextBody(linkURL, cfg.TTLSeconds)

	if err := sender.Send(req.Email, subject, htmlBody, textBody); err != nil {
		log.Error("failed to send magic link email", logger.Err(err))
		return fmt.Errorf("failed to send magic link email: %w", err)
	}

	return nil
}

func (s *passwordlessService) VerifyMagicLink(ctx context.Context, token string) (*dtoa.LoginResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("passwordless.magiclink"))

	session, err := s.consumeMagicLinkToken(ctx, token)
	if err != nil {
		return nil, err
	}

	log.Info("magic link verified",
		logger.String("tenant_id", session.TenantID),
	)

	resp, err := s.issueJWT(ctx, session.TenantID, session.ClientID, session.Email, "magic_link")
	if err != nil {
		s.emitPasswordlessFailure(ctx, session.TenantID, "magic_link", "token_issuance_failed", session.ClientID)
		return nil, err
	}
	return resp, nil
}

func (s *passwordlessService) ConsumeMagicLink(ctx context.Context, token string) (string, error) {
	session, err := s.consumeMagicLinkToken(ctx, token)
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(session.RedirectURI) == "" {
		s.emitPasswordlessFailure(ctx, session.TenantID, "magic_link", "invalid_redirect_uri", session.ClientID)
		return "", ErrInvalidRedirectURI
	}
	if s.deps.Cache == nil {
		s.emitPasswordlessFailure(ctx, session.TenantID, "magic_link", "cache_not_configured", session.ClientID)
		return "", ErrCacheNotConfigured
	}

	code, err := security.GenerateOpaqueToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate magic link code: %w", err)
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("failed to marshal magic link code session: %w", err)
	}

	if err := s.deps.Cache.Set(ctx, MagicLinkCodeCacheKey(code), string(payload), 90*time.Second); err != nil {
		s.emitPasswordlessFailure(ctx, session.TenantID, "magic_link", "store_code_session_failed", session.ClientID)
		return "", fmt.Errorf("failed to store magic link code session: %w", err)
	}

	redirectURL, err := url.Parse(session.RedirectURI)
	if err != nil || !redirectURL.IsAbs() {
		s.emitPasswordlessFailure(ctx, session.TenantID, "magic_link", "invalid_redirect_uri", session.ClientID)
		return "", ErrInvalidRedirectURI
	}

	redirectURL.Fragment = url.Values{"magic_link_code": {code}}.Encode()
	return redirectURL.String(), nil
}

func (s *passwordlessService) ExchangeMagicLinkCode(ctx context.Context, code string) (*dtoa.LoginResponse, error) {
	if strings.TrimSpace(code) == "" {
		s.emitPasswordlessFailure(ctx, "", "magic_link", "invalid_or_expired_magic_link_code", "")
		return nil, ErrInvalidOrExpiredMagicCode
	}
	if s.deps.Cache == nil {
		s.emitPasswordlessFailure(ctx, "", "magic_link", "cache_not_configured", "")
		return nil, ErrCacheNotConfigured
	}

	cachedVal, err := s.deps.Cache.GetDel(ctx, MagicLinkCodeCacheKey(code))
	if err != nil {
		if cache.IsNotFound(err) {
			s.emitPasswordlessFailure(ctx, "", "magic_link", "invalid_or_expired_magic_link_code", "")
			return nil, ErrInvalidOrExpiredMagicCode
		}
		s.emitPasswordlessFailure(ctx, "", "magic_link", "cache_error", "")
		return nil, fmt.Errorf("cache error: %w", err)
	}

	var session magicLinkSession
	if err := json.Unmarshal([]byte(cachedVal), &session); err != nil {
		s.emitPasswordlessFailure(ctx, "", "magic_link", "corrupted_magic_link_code_session", "")
		return nil, ErrInvalidOrExpiredMagicCode
	}

	resp, err := s.issueJWT(ctx, session.TenantID, session.ClientID, session.Email, "magic_link")
	if err != nil {
		s.emitPasswordlessFailure(ctx, session.TenantID, "magic_link", "token_issuance_failed", session.ClientID)
		return nil, err
	}
	return resp, nil
}

func (s *passwordlessService) consumeMagicLinkToken(ctx context.Context, token string) (*magicLinkSession, error) {
	if strings.TrimSpace(token) == "" {
		s.emitPasswordlessFailure(ctx, "", "magic_link", "invalid_or_expired_magic_link", "")
		return nil, ErrInvalidOrExpiredMagicLink
	}
	if s.deps.Cache == nil {
		s.emitPasswordlessFailure(ctx, "", "magic_link", "cache_not_configured", "")
		return nil, ErrCacheNotConfigured
	}

	cachedVal, err := s.deps.Cache.GetDel(ctx, MagicLinkCacheKey(token))
	if err != nil {
		if cache.IsNotFound(err) {
			s.emitPasswordlessFailure(ctx, "", "magic_link", "invalid_or_expired_magic_link", "")
			return nil, ErrInvalidOrExpiredMagicLink
		}
		s.emitPasswordlessFailure(ctx, "", "magic_link", "cache_error", "")
		return nil, fmt.Errorf("cache error: %w", err)
	}

	var session magicLinkSession
	if err := json.Unmarshal([]byte(cachedVal), &session); err != nil {
		s.emitPasswordlessFailure(ctx, "", "magic_link", "corrupted_magic_link_session", "")
		return nil, fmt.Errorf("corrupted magic link session: %w", err)
	}

	return &session, nil
}

func (s *passwordlessService) emitPasswordlessFailure(ctx context.Context, tenantID, method, reason, clientID string) {
	if s.deps.AuditBus == nil {
		return
	}
	if strings.TrimSpace(tenantID) == "" {
		tenantID = audit.ControlPlaneTenantID
	}
	evt := audit.NewEvent(audit.EventLoginFailed, tenantID).
		WithActor("", audit.ActorSystem).
		WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
		WithResult(audit.ResultFailure).
		WithMeta("method", method).
		WithMeta("reason", reason)
	if strings.TrimSpace(clientID) != "" {
		evt = evt.WithMeta("client_id", clientID)
	}
	s.deps.AuditBus.Emit(evt)
}

// ─────────────────────────────────────────────────────────────
// OTP Email
// ─────────────────────────────────────────────────────────────

func (s *passwordlessService) SendOTPEmail(ctx context.Context, req OTPRequest) error {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("passwordless.otp"))
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if req.Email == "" || req.TenantSlug == "" {
		return fmt.Errorf("email and tenant_id are required")
	}

	tda, err := s.deps.DAL.ForTenant(ctx, req.TenantSlug)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	settings := tda.Settings()
	if settings.Passwordless == nil || !settings.Passwordless.OTP.Enabled {
		return ErrOTPDisabled
	}
	cfg := settings.Passwordless.OTP

	if s.deps.Cache == nil {
		return ErrCacheNotConfigured
	}

	// Rate limiting: 1 request per minute per email
	rateKey := OTPRateLimitKey(req.TenantSlug, req.Email)
	if _, err := s.deps.Cache.Get(ctx, rateKey); err == nil {
		return ErrRateLimited
	}

	// Rate limiting: daily cap
	dailyCapKey := fmt.Sprintf("rl:otp:daily:%s:%s:%s", req.TenantSlug, req.Email, time.Now().UTC().Format("2006-01-02"))
	dailyLimit := cfg.DailyMaxEmails
	if dailyLimit == 0 {
		dailyLimit = 10
	}
	if dailyLimit > 0 {
		countStr, _ := s.deps.Cache.Get(ctx, dailyCapKey)
		var count int
		if countStr != "" {
			fmt.Sscanf(countStr, "%d", &count)
		}
		if count >= dailyLimit {
			return ErrDailyLimitExceeded
		}
		_ = s.deps.Cache.Set(ctx, dailyCapKey, fmt.Sprintf("%d", count+1), 25*time.Hour)
	}

	// Generate OTP code
	codeLen := cfg.Length
	if codeLen == 0 {
		codeLen = 6
	}
	rawCode, err := security.GenerateOTP(codeLen)
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	// Store hashed OTP (zero-knowledge)
	cacheKey := OTPCacheKey(tda.ID(), req.Email)
	session := otpSession{
		CodeHash:  hashOTP(rawCode),
		Attempts:  0,
		TenantID:  tda.ID(),
		ClientID:  req.ClientID,
		ExpiresAt: time.Now().Add(ttl),
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal OTP session: %w", err)
	}

	if err := s.deps.Cache.Set(ctx, cacheKey, string(payload), ttl); err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	// Set rate limit (1 minute cooldown)
	_ = s.deps.Cache.Set(ctx, rateKey, "1", 60*time.Second)

	log.Info("OTP generated",
		logger.TenantID(req.TenantSlug),
	)

	sender, err := s.deps.Email.GetSender(ctx, req.TenantSlug)
	if err != nil {
		log.Error("failed to get email sender for OTP", logger.Err(err))
		return fmt.Errorf("failed to send OTP email")
	}

	subject := "Tu código de acceso"
	htmlBody := otpHTMLBody(rawCode, cfg.TTLSeconds)
	textBody := otpTextBody(rawCode, cfg.TTLSeconds)

	if err := sender.Send(req.Email, subject, htmlBody, textBody); err != nil {
		log.Error("failed to send OTP email", logger.Err(err))
		return fmt.Errorf("failed to send OTP email: %w", err)
	}

	return nil
}

func (s *passwordlessService) VerifyOTPEmail(ctx context.Context, req VerifyOTPRequest) (*dtoa.LoginResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("passwordless.otp"))
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if req.Email == "" || req.TenantSlug == "" || req.Code == "" {
		return nil, fmt.Errorf("email, tenant_id, and code are required")
	}

	tda, err := s.deps.DAL.ForTenant(ctx, req.TenantSlug)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	if s.deps.Cache == nil {
		return nil, fmt.Errorf("cache not configured")
	}

	cacheKey := OTPCacheKey(tda.ID(), req.Email)
	cachedVal, err := s.deps.Cache.Get(ctx, cacheKey)
	if err != nil {
		if cache.IsNotFound(err) {
			// Audit: expired/invalid OTP
			if s.deps.AuditBus != nil {
				s.deps.AuditBus.Emit(
					audit.NewEvent(audit.EventLoginFailed, tda.ID()).
						WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
						WithResult(audit.ResultFailure).
						WithMeta("method", "otp").
						WithMeta("reason", "expired_or_invalid").
						WithMeta("otp_channel", "email"),
				)
			}
			return nil, fmt.Errorf("invalid or expired OTP")
		}
		return nil, fmt.Errorf("cache error: %w", err)
	}

	var session otpSession
	if err := json.Unmarshal([]byte(cachedVal), &session); err != nil {
		return nil, fmt.Errorf("corrupted OTP session: %w", err)
	}

	// Check code hash
	hashInput := hashOTP(req.Code)
	if subtle.ConstantTimeCompare([]byte(session.CodeHash), []byte(hashInput)) != 1 {
		session.Attempts++

		// Audit: OTP verification failure
		if s.deps.AuditBus != nil {
			reason := "incorrect_code"
			if session.Attempts >= 5 {
				reason = "max_attempts_exceeded"
			}
			s.deps.AuditBus.Emit(
				audit.NewEvent(audit.EventLoginFailed, tda.ID()).
					WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
					WithResult(audit.ResultFailure).
					WithMeta("method", "otp").
					WithMeta("reason", reason).
					WithMeta("otp_channel", "email"),
			)
		}

		if session.Attempts >= 5 {
			// Too many failed attempts — purge to force rotation
			_ = s.deps.Cache.Delete(ctx, cacheKey)
			log.Warn("OTP purged after 5 failed attempts",
				logger.TenantID(req.TenantSlug),
			)
			return nil, fmt.Errorf("too many failed attempts, request a new code")
		}
		// Update attempts counter
		newPayload, _ := json.Marshal(session)
		remaining := time.Until(session.ExpiresAt)
		if remaining <= 0 {
			_ = s.deps.Cache.Delete(ctx, cacheKey)
			return nil, ErrInvalidOrExpiredOTP
		}
		_ = s.deps.Cache.Set(ctx, cacheKey, string(newPayload), remaining)
		return nil, fmt.Errorf("incorrect OTP (%d/5 attempts)", session.Attempts)
	}

	// Success: One-Shot destruction
	if err := s.deps.Cache.Delete(ctx, cacheKey); err != nil {
		log.Warn("failed to delete one-shot token from cache",
			logger.Err(err),
		)
	}

	log.Info("OTP verified",
		logger.TenantID(req.TenantSlug),
	)

	return s.issueJWT(ctx, session.TenantID, session.ClientID, req.Email, "otp")
}

// ─────────────────────────────────────────────────────────────
// JWT Issuance + Auto-Register (Fase 3.4)
// ─────────────────────────────────────────────────────────────

func (s *passwordlessService) issueJWT(ctx context.Context, tenantID, clientID, email, authMethod string) (*dtoa.LoginResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("passwordless.issue"))

	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	if err := tda.RequireDB(); err != nil {
		return nil, fmt.Errorf("%w: passwordless auth requires database", ErrNoDatabase)
	}

	user, _, err := tda.Users().GetByEmail(ctx, tenantID, email)

	// Auto-Register check
	if errors.Is(err, repository.ErrNotFound) {
		cfg := tda.Settings().Passwordless
		if cfg == nil {
			return nil, ErrAuthenticationFailed
		}

		autoRegEnabled := false
		switch authMethod {
		case "magic_link":
			autoRegEnabled = cfg.MagicLink.AutoRegister
		case "otp":
			autoRegEnabled = cfg.OTP.AutoRegister
		}

		if !autoRegEnabled {
			return nil, ErrAuthenticationFailed
		}

		// Create user silently
		user, _, err = tda.Users().Create(ctx, repository.CreateUserInput{
			TenantID: tenantID,
			Email:    email,
			Provider: authMethod,
		})
		if err != nil {
			return nil, fmt.Errorf("auto-register failed: %w", err)
		}

		// Mark email as verified (proven by magic link / OTP possession)
		if err := tda.Users().SetEmailVerified(ctx, user.ID, true); err != nil {
			log.Error("failed to set email_verified on auto-registered user",
				logger.Err(err),
				logger.String("user_id", user.ID),
			)
		}

		log.Info("auto-registered user via passwordless",
			logger.String("method", authMethod),
			logger.String("user_id", user.ID),
		)
	} else if err != nil {
		return nil, ErrAuthenticationFailed
	}

	// Issue JWT tokens using the same pattern as login
	if s.deps.Issuer == nil {
		return nil, fmt.Errorf("issuer not configured")
	}

	amr := []string{authMethod}
	stdClaims := map[string]any{
		"amr": amr,
	}
	accessToken, _, err := s.deps.Issuer.IssueAccessForTenant(tenantID, "", user.ID, clientID, stdClaims, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to issue access token: %w", err)
	}

	// Issue refresh token
	refreshTTL := s.deps.RefreshTTL
	if refreshTTL == 0 {
		refreshTTL = 24 * time.Hour
	}

	refreshToken := ""
	if tda.Tokens() != nil {
		refreshTTLSeconds := int(refreshTTL.Seconds())
		rt, err := tda.Tokens().Create(ctx, repository.CreateRefreshTokenInput{
			TenantID:   tenantID,
			UserID:     user.ID,
			ClientID:   clientID,
			TTLSeconds: refreshTTLSeconds,
		})
		if err == nil {
			refreshToken = rt
		}
	}

	expiresIn := int64(3600)
	if s.deps.Issuer != nil {
		expiresIn = int64(s.deps.Issuer.AccessTTL.Seconds())
	}

	// Audit: passwordless login success
	if s.deps.AuditBus != nil {
		eventType := audit.EventMagicLink
		if authMethod == "otp" {
			eventType = audit.EventOTPLogin
		}
		s.deps.AuditBus.Emit(
			audit.NewEvent(eventType, tenantID).
				WithActor(user.ID, audit.ActorUser).
				WithTarget(user.ID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithResult(audit.ResultSuccess).
				WithMeta("method", authMethod).
				WithMeta("client_id", clientID),
		)
	}

	return &dtoa.LoginResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
	}, nil
}

// ── Helpers ──

func magicLinkHTMLBody(linkURL string, ttlSeconds int) string {
	return fmt.Sprintf("<p>Tu enlace de acceso:</p><p><a href=\"%s\">Ingresar</a></p><p>Válido por %d segundos.</p>", linkURL, ttlSeconds)
}
func magicLinkTextBody(linkURL string, ttlSeconds int) string {
	return fmt.Sprintf("Tu enlace de acceso: %s (Válido por %d segundos)", linkURL, ttlSeconds)
}
func otpHTMLBody(code string, ttlSeconds int) string {
	return fmt.Sprintf("<p>Tu código OTP es:</p><h2>%s</h2><p>Válido por %d segundos.</p>", code, ttlSeconds)
}
func otpTextBody(code string, ttlSeconds int) string {
	return fmt.Sprintf("Tu código OTP es: %s (Válido por %d segundos)", code, ttlSeconds)
}

func isValidRedirectURI(uri string, allowed []string) bool {
	canonicalURI, ok := canonicalizePasswordlessRedirectURI(uri)
	if !ok {
		return false
	}

	for _, a := range allowed {
		canonicalAllowed, ok := canonicalizePasswordlessRedirectURI(a)
		if ok && canonicalAllowed == canonicalURI {
			return true
		}
	}
	return false
}

func canonicalizePasswordlessRedirectURI(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "*") {
		return "", false
	}

	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return "", false
	}
	if u.Fragment != "" {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme != "https" {
		if scheme != "http" || !(host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" || strings.HasPrefix(host, "127.")) {
			return "", false
		}
	}

	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		u.Host = u.Hostname()
	}
	u.Fragment = ""
	return u.String(), true
}
