package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/domain/types"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	walib "github.com/dropDatabas3/hellojohn/internal/security/webauthn"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// WebAuthnAuthService orquesta ceremonias WebAuthn y emision de tokens.
type WebAuthnAuthService interface {
	BeginRegistration(ctx context.Context, tenantSlug, userID string) (optionsJSON []byte, sessionID string, err error)
	FinishRegistration(ctx context.Context, tenantSlug, sessionID string, bodyJSON []byte, credentialName string) error
	BeginLogin(ctx context.Context, tenantSlug, email string) (optionsJSON []byte, sessionID string, err error)
	FinishLogin(ctx context.Context, tenantSlug, sessionID string, bodyJSON []byte) (*dto.LoginResult, error)
}

// WebAuthnDeps define dependencias de WebAuthnAuthService.
type WebAuthnDeps struct {
	DAL        store.DataAccessLayer
	Issuer     *jwtx.Issuer
	RefreshTTL time.Duration
	ClaimsHook ClaimsHook
	BaseURL    string
}

type webAuthnAuthService struct {
	deps WebAuthnDeps
}

// NewWebAuthnAuthService crea una instancia de WebAuthnAuthService.
func NewWebAuthnAuthService(deps WebAuthnDeps) WebAuthnAuthService {
	if deps.ClaimsHook == nil {
		deps.ClaimsHook = NoOpClaimsHook{}
	}
	return &webAuthnAuthService{deps: deps}
}

func (s *webAuthnAuthService) BeginRegistration(ctx context.Context, tenantSlug, userID string) ([]byte, string, error) {
	tenantSlug = strings.TrimSpace(tenantSlug)
	userID = strings.TrimSpace(userID)
	if tenantSlug == "" {
		return nil, "", ErrWebAuthnTenantRequired
	}
	if userID == "" {
		return nil, "", ErrWebAuthnUserRequired
	}

	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, "", err
	}
	if err := tda.RequireDB(); err != nil {
		return nil, "", err
	}

	user, err := tda.Users().GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, "", ErrWebAuthnUserNotFound
		}
		return nil, "", err
	}

	service, err := s.buildWAService(tenantSlug, tda)
	if err != nil {
		return nil, "", err
	}

	displayName := strings.TrimSpace(user.Name)
	if displayName == "" {
		displayName = strings.TrimSpace(user.Email)
	}
	if displayName == "" {
		displayName = userID
	}

	optionsJSON, sessionID, err := service.BeginRegistration(
		ctx,
		tenantSlug,
		tda.ID(),
		userID,
		strings.TrimSpace(user.Email),
		displayName,
	)
	if err != nil {
		return nil, "", mapWALibError(err)
	}
	return optionsJSON, sessionID, nil
}

func (s *webAuthnAuthService) FinishRegistration(ctx context.Context, tenantSlug, sessionID string, bodyJSON []byte, credentialName string) error {
	tenantSlug = strings.TrimSpace(tenantSlug)
	sessionID = strings.TrimSpace(sessionID)
	if tenantSlug == "" {
		return ErrWebAuthnTenantRequired
	}
	if sessionID == "" {
		return ErrWebAuthnSessionRequired
	}
	if len(bodyJSON) == 0 {
		return ErrWebAuthnResponseRequired
	}

	userID, err := extractUserIDFromSession(sessionID)
	if err != nil {
		return err
	}

	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return err
	}
	if err := tda.RequireDB(); err != nil {
		return err
	}

	service, err := s.buildWAService(tenantSlug, tda)
	if err != nil {
		return err
	}

	if err := service.FinishRegistration(
		ctx,
		tenantSlug,
		tda.ID(),
		userID,
		sessionID,
		bodyJSON,
		strings.TrimSpace(credentialName),
	); err != nil {
		return mapWALibError(err)
	}

	return nil
}

func (s *webAuthnAuthService) BeginLogin(ctx context.Context, tenantSlug, email string) ([]byte, string, error) {
	tenantSlug = strings.TrimSpace(tenantSlug)
	email = strings.TrimSpace(strings.ToLower(email))
	if tenantSlug == "" {
		return nil, "", ErrWebAuthnTenantRequired
	}
	if email == "" {
		return nil, "", ErrWebAuthnEmailRequired
	}

	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, "", err
	}
	if err := tda.RequireDB(); err != nil {
		return nil, "", err
	}

	user, _, err := tda.Users().GetByEmail(ctx, tda.ID(), email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, "", ErrWebAuthnUserNotFound
		}
		return nil, "", err
	}

	service, err := s.buildWAService(tenantSlug, tda)
	if err != nil {
		return nil, "", err
	}

	optionsJSON, sessionID, err := service.BeginLogin(ctx, tenantSlug, tda.ID(), user.ID)
	if err != nil {
		return nil, "", mapWALibError(err)
	}
	return optionsJSON, sessionID, nil
}

func (s *webAuthnAuthService) FinishLogin(ctx context.Context, tenantSlug, sessionID string, bodyJSON []byte) (*dto.LoginResult, error) {
	tenantSlug = strings.TrimSpace(tenantSlug)
	sessionID = strings.TrimSpace(sessionID)
	if tenantSlug == "" {
		return nil, ErrWebAuthnTenantRequired
	}
	if sessionID == "" {
		return nil, ErrWebAuthnSessionRequired
	}
	if len(bodyJSON) == 0 {
		return nil, ErrWebAuthnResponseRequired
	}

	userID, err := extractUserIDFromSession(sessionID)
	if err != nil {
		return nil, err
	}

	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	service, err := s.buildWAService(tenantSlug, tda)
	if err != nil {
		return nil, err
	}

	verifiedUserID, err := service.FinishLogin(ctx, tenantSlug, tda.ID(), userID, sessionID, bodyJSON)
	if err != nil {
		return nil, mapWALibError(err)
	}

	user, err := tda.Users().GetByID(ctx, verifiedUserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrWebAuthnUserNotFound
		}
		return nil, err
	}

	result, err := s.issueTokensForUser(ctx, tda, user.ID)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *webAuthnAuthService) issueTokensForUser(ctx context.Context, tda store.TenantDataAccess, userID string) (*dto.LoginResult, error) {
	if s.deps.Issuer == nil {
		return nil, ErrWebAuthnTokenIssueFailed
	}

	clientID, scopes, err := resolveWebAuthnClient(ctx, tda)
	if err != nil {
		return nil, err
	}

	accessToken, exp, err := s.issueAccessToken(ctx, tda, userID, clientID, scopes)
	if err != nil {
		return nil, err
	}

	rawRefresh, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		return nil, ErrWebAuthnTokenIssueFailed
	}
	refreshHash := tokens.SHA256Base64URL(rawRefresh)

	refreshTTL := s.deps.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = 24 * time.Hour
	}

	if _, err := tda.Tokens().Create(ctx, repository.CreateRefreshTokenInput{
		TenantID:   tda.ID(),
		ClientID:   clientID,
		UserID:     userID,
		TokenHash:  refreshHash,
		TTLSeconds: int(refreshTTL.Seconds()),
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWebAuthnTokenIssueFailed, err)
	}

	return &dto.LoginResult{
		Success:      true,
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int64(time.Until(exp).Seconds()),
	}, nil
}

func (s *webAuthnAuthService) issueAccessToken(ctx context.Context, tda store.TenantDataAccess, userID, clientID string, scopes []string) (string, time.Time, error) {
	tenantID := tda.ID()
	amr := []string{"webauthn"}
	std := map[string]any{
		"tid": tenantID,
		"amr": amr,
		"acr": "urn:hellojohn:loa:2",
		"scp": strings.Join(scopes, " "),
	}
	custom := map[string]any{}

	std, custom = s.deps.ClaimsHook.ApplyAccess(ctx, tenantID, clientID, userID, scopes, amr, std, custom)

	effIss := jwtx.ResolveIssuer(
		s.deps.Issuer.Iss,
		string(tda.Settings().IssuerMode),
		tda.Slug(),
		tda.Settings().IssuerOverride,
	)
	custom = helpers.PutSystemClaimsV2(custom, effIss, nil, nil, nil)

	kid, priv, _, err := s.selectSigningKey(tda)
	if err != nil {
		return "", time.Time{}, ErrWebAuthnTokenIssueFailed
	}

	now := time.Now().UTC()
	exp := now.Add(s.deps.Issuer.AccessTTL)

	claims := jwtv5.MapClaims{
		"iss": effIss,
		"sub": userID,
		"aud": clientID,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
	}
	for k, v := range std {
		claims[k] = v
	}
	if len(custom) > 0 {
		claims["custom"] = custom
	}

	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"

	accessToken, err := tk.SignedString(priv)
	if err != nil {
		return "", time.Time{}, ErrWebAuthnTokenIssueFailed
	}
	return accessToken, exp, nil
}

func (s *webAuthnAuthService) selectSigningKey(tda store.TenantDataAccess) (kid string, priv any, pub any, err error) {
	settings := tda.Settings()
	if types.IssuerMode(settings.IssuerMode) == types.IssuerModePath {
		return s.deps.Issuer.Keys.ActiveForTenant(tda.Slug())
	}
	return s.deps.Issuer.Keys.Active()
}

func (s *webAuthnAuthService) buildWAService(tenantSlug string, tda store.TenantDataAccess) (*walib.Service, error) {
	cfg, err := s.resolveConfig(tenantSlug, tda.Settings())
	if err != nil {
		return nil, err
	}

	cacheClient := tda.Cache()
	if cacheClient == nil {
		return nil, ErrWebAuthnCacheUnavailable
	}
	return walib.New(cfg, tda.WebAuthn(), cacheClient), nil
}

func (s *webAuthnAuthService) resolveConfig(tenantSlug string, settings *repository.TenantSettings) (walib.Config, error) {
	cfg := walib.Config{}
	if settings != nil {
		cfg.RPID = strings.TrimSpace(settings.WebAuthn.RPID)
		cfg.RPOrigins = normalizeOrigins(settings.WebAuthn.RPOrigins)
		cfg.RPDisplayName = strings.TrimSpace(settings.WebAuthn.RPDisplayName)
	}

	if cfg.RPID == "" {
		if host := hostFromBaseURL(strings.TrimSpace(s.deps.BaseURL)); host != "" {
			cfg.RPID = host
		}
	}
	if cfg.RPID == "" {
		cfg.RPID = hostFromOrigins(cfg.RPOrigins)
	}
	if cfg.RPID == "" {
		return walib.Config{}, ErrWebAuthnRPIDRequired
	}

	if len(cfg.RPOrigins) == 0 {
		cfg.RPOrigins = []string{"https://" + cfg.RPID}
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = tenantSlug
	}
	return cfg, nil
}

func resolveWebAuthnClient(ctx context.Context, tda store.TenantDataAccess) (string, []string, error) {
	clients, err := tda.Clients().List(ctx, "")
	if err != nil {
		return "", nil, err
	}
	if len(clients) == 0 {
		return "", nil, ErrWebAuthnNoClient
	}

	for _, c := range clients {
		if strings.TrimSpace(c.ClientID) == "" {
			continue
		}
		if helpers.IsPasswordProviderAllowed(c.Providers) {
			return c.ClientID, c.Scopes, nil
		}
	}

	for _, c := range clients {
		if strings.TrimSpace(c.ClientID) != "" {
			return c.ClientID, c.Scopes, nil
		}
	}
	return "", nil, ErrWebAuthnNoClient
}

func extractUserIDFromSession(sessionID string) (string, error) {
	parts := strings.SplitN(sessionID, ":", 2)
	if len(parts) != 2 {
		return "", ErrWebAuthnInvalidSessionID
	}
	userID := strings.TrimSpace(parts[0])
	if userID == "" {
		return "", ErrWebAuthnInvalidSessionID
	}
	return userID, nil
}

func normalizeOrigins(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func hostFromBaseURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Hostname())
}

func hostFromOrigins(origins []string) string {
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil {
			continue
		}
		host := strings.TrimSpace(u.Hostname())
		if host != "" {
			return host
		}
	}
	return ""
}

func mapWALibError(err error) error {
	switch {
	case errors.Is(err, walib.ErrChallengeExpiredOrNotFound):
		return ErrWebAuthnChallengeExpired
	case errors.Is(err, walib.ErrNoCredentialsRegistered):
		return ErrWebAuthnNoCredentials
	case errors.Is(err, walib.ErrPotentialCredentialClone):
		return ErrWebAuthnCredentialCloneWarning
	case errors.Is(err, walib.ErrSessionUserMismatch):
		return ErrWebAuthnInvalidSessionID
	default:
		return err
	}
}

var (
	ErrWebAuthnTenantRequired         = errors.New("webauthn: tenant is required")
	ErrWebAuthnUserRequired           = errors.New("webauthn: user is required")
	ErrWebAuthnEmailRequired          = errors.New("webauthn: email is required")
	ErrWebAuthnSessionRequired        = errors.New("webauthn: session is required")
	ErrWebAuthnResponseRequired       = errors.New("webauthn: response is required")
	ErrWebAuthnInvalidSessionID       = errors.New("webauthn: invalid session id")
	ErrWebAuthnUserNotFound           = errors.New("webauthn: user not found")
	ErrWebAuthnNoCredentials          = errors.New("webauthn: no credentials registered")
	ErrWebAuthnChallengeExpired       = errors.New("webauthn: challenge expired or not found")
	ErrWebAuthnCredentialCloneWarning = errors.New("webauthn: credential clone warning")
	ErrWebAuthnRPIDRequired           = errors.New("webauthn: rpid could not be resolved")
	ErrWebAuthnNoClient               = errors.New("webauthn: no available client for tenant")
	ErrWebAuthnTokenIssueFailed       = errors.New("webauthn: failed to issue tokens")
	ErrWebAuthnCacheUnavailable       = errors.New("webauthn: cache unavailable")
)
