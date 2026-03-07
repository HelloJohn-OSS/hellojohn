package session

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
)

const defaultSessionTokenTTL = 5 * time.Minute

// SessionTokenIssuer mints signed JWTs from active sessions.
type SessionTokenIssuer interface {
	MintSessionToken(sub, tenantID string, ttl time.Duration) (string, time.Time, error)
}

// SessionTokenService defines operations for session-token minting.
type SessionTokenService interface {
	MintFromSession(ctx context.Context, sessionID string) (*SessionTokenResult, error)
}

// SessionTokenResult contains the minted token and ttl.
type SessionTokenResult struct {
	Token     string
	ExpiresIn int64
}

// SessionTokenDeps contains dependencies for session token minting.
type SessionTokenDeps struct {
	Cache    Cache
	Issuer   SessionTokenIssuer
	TokenTTL time.Duration
}

type sessionTokenService struct {
	cache    Cache
	issuer   SessionTokenIssuer
	tokenTTL time.Duration
}

// NewSessionTokenService creates a new session token service.
func NewSessionTokenService(deps SessionTokenDeps) SessionTokenService {
	ttl := deps.TokenTTL
	if ttl <= 0 {
		ttl = defaultSessionTokenTTL
	}
	return &sessionTokenService{
		cache:    deps.Cache,
		issuer:   deps.Issuer,
		tokenTTL: ttl,
	}
}

// Session token service errors.
var (
	ErrSessionTokenMissingSession = fmt.Errorf("missing session id")
	ErrSessionTokenNotFound       = fmt.Errorf("session not found")
	ErrSessionTokenInvalidSession = fmt.Errorf("invalid session payload")
	ErrSessionTokenExpired        = fmt.Errorf("session expired")
	ErrSessionTokenMintFailed     = fmt.Errorf("failed to mint session token")
)

func (s *sessionTokenService) MintFromSession(ctx context.Context, sessionID string) (*SessionTokenResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("session.token"),
		logger.Op("MintFromSession"),
	)

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, ErrSessionTokenMissingSession
	}
	if s.cache == nil || s.issuer == nil {
		log.Error("session token dependencies not configured")
		return nil, ErrSessionTokenMintFailed
	}

	key := "sid:" + tokens.SHA256Base64URL(sessionID)
	raw, ok := s.cache.Get(key)
	if !ok || len(raw) == 0 {
		return nil, ErrSessionTokenNotFound
	}

	var payload dto.SessionPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		_ = s.cache.Delete(key)
		return nil, ErrSessionTokenInvalidSession
	}

	if strings.TrimSpace(payload.UserID) == "" || strings.TrimSpace(payload.TenantID) == "" || payload.Expires.IsZero() {
		_ = s.cache.Delete(key)
		return nil, ErrSessionTokenInvalidSession
	}

	if !time.Now().Before(payload.Expires) {
		_ = s.cache.Delete(key)
		return nil, ErrSessionTokenExpired
	}

	token, exp, err := s.issuer.MintSessionToken(payload.UserID, payload.TenantID, s.tokenTTL)
	if err != nil {
		log.Error("failed to mint session token", logger.Err(err))
		return nil, ErrSessionTokenMintFailed
	}

	expiresIn := int64(time.Until(exp).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

	log.Debug("session token minted")
	return &SessionTokenResult{
		Token:     token,
		ExpiresIn: expiresIn,
	}, nil
}
