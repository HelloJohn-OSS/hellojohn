package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"go.uber.org/zap"
)

// LoginService defines operations for session-based login.
type LoginService interface {
	Login(ctx context.Context, tda store.TenantDataAccess, req dto.LoginRequest) (*LoginResult, error)
	BuildSessionCookie(sessionID string, config dto.LoginConfig) *http.Cookie
}

// LoginResult contains the result of a successful login.
type LoginResult struct {
	SessionID string
	UserID    string
	TenantID  string
	ExpiresAt time.Time
}

// LoginDeps contains dependencies for the login service.
type LoginDeps struct {
	Cache  Cache
	Config dto.LoginConfig
}

type loginService struct {
	cache  Cache
	config dto.LoginConfig
}

// NewLoginService creates a new LoginService.
func NewLoginService(deps LoginDeps) LoginService {
	cfg := deps.Config
	if cfg.CookieName == "" {
		cfg.CookieName = "sid"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	return &loginService{
		cache:  deps.Cache,
		config: cfg,
	}
}

// Service errors
var (
	ErrLoginMissingTenant      = fmt.Errorf("tenant_id or client_id is required")
	ErrLoginMissingEmail       = fmt.Errorf("email is required")
	ErrLoginMissingPassword    = fmt.Errorf("password is required")
	ErrLoginInvalidCredentials = fmt.Errorf("invalid credentials")
	ErrLoginNoDatabase         = fmt.Errorf("database not available")
	ErrLoginUserNotFound       = fmt.Errorf("user not found")
	ErrLoginSessionFailed      = fmt.Errorf("failed to create session")
)

// Login authenticates a user and creates a session.
func (s *loginService) Login(ctx context.Context, tda store.TenantDataAccess, req dto.LoginRequest) (*LoginResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("session.login"),
		logger.Op("Login"),
	)

	// Validate input
	email := strings.TrimSpace(strings.ToLower(req.Email))
	password := req.Password

	if req.TenantID == "" && req.ClientID == "" {
		return nil, ErrLoginMissingTenant
	}
	if email == "" {
		return nil, ErrLoginMissingEmail
	}
	if password == "" {
		return nil, ErrLoginMissingPassword
	}

	// Require database for authentication
	if err := tda.RequireDB(); err != nil {
		log.Debug("database not available", logger.Err(err))
		return nil, ErrLoginNoDatabase
	}

	// Get user by email (returns user + identity in one call)
	usersRepo := tda.Users()
	tenantIDForLookup := req.TenantID
	if tenantIDForLookup == "" {
		tenantIDForLookup = req.ClientID // Fallback to client_id as tenant identifier
	}
	user, identity, err := usersRepo.GetByEmail(ctx, tenantIDForLookup, email)
	if err != nil {
		log.Debug("user lookup failed", logger.Err(err))
		return nil, ErrLoginInvalidCredentials
	}
	if identity == nil || identity.PasswordHash == nil {
		log.Debug("identity not found or no password")
		return nil, ErrLoginInvalidCredentials
	}

	// Verify password
	if !usersRepo.CheckPassword(identity.PasswordHash, password) {
		log.Debug("password mismatch")
		return nil, ErrLoginInvalidCredentials
	}

	// Generate session ID
	sessionID, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		log.Error("failed to generate session ID", logger.Err(err))
		return nil, ErrLoginSessionFailed
	}

	// Create session payload (use user's tenant or request tenant)
	tenantID := user.TenantID
	if tenantID == "" {
		tenantID = req.TenantID
	}

	expiresAt := time.Now().Add(s.config.TTL)
	payload := dto.SessionPayload{
		UserID:   user.ID,
		TenantID: tenantID,
		Expires:  expiresAt,
	}

	// Store in cache
	key := "sid:" + tokens.SHA256Base64URL(sessionID)
	payloadBytes, _ := json.Marshal(payload)
	if s.cache == nil {
		log.Error("session cache not configured")
		return nil, ErrLoginSessionFailed
	}
	if err := s.cache.Set(key, payloadBytes, s.config.TTL); err != nil {
		log.Error("failed to store session in cache", logger.Err(err))
		return nil, ErrLoginSessionFailed
	}

	log.Debug("session created",
		zap.String("user_id", user.ID),
		zap.String("tenant_id", tenantID),
	)

	return &LoginResult{
		SessionID: sessionID,
		UserID:    user.ID,
		TenantID:  tenantID,
		ExpiresAt: expiresAt,
	}, nil
}

// BuildSessionCookie creates a session cookie.
func (s *loginService) BuildSessionCookie(sessionID string, config dto.LoginConfig) *http.Cookie {
	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = "sid"
	}

	ttl := config.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	sameSite := http.SameSiteLaxMode
	switch config.SameSite {
	case "Strict":
		sameSite = http.SameSiteStrictMode
	case "None":
		sameSite = http.SameSiteNoneMode
	case "Lax":
		sameSite = http.SameSiteLaxMode
	}

	return &http.Cookie{
		Name:     cookieName,
		Value:    sessionID,
		Path:     "/",
		Domain:   config.CookieDomain,
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Now().Add(ttl),
		HttpOnly: true,
		Secure:   config.Secure,
		SameSite: sameSite,
	}
}
