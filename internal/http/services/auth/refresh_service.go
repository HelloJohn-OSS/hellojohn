package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/domain/types"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// RefreshService defines operations for token refresh.
type RefreshService interface {
	Refresh(ctx context.Context, in dto.RefreshRequest, tenantSlug string) (*dto.RefreshResult, error)
}

// RefreshDeps contains dependencies for the refresh service.
type RefreshDeps struct {
	DAL                   store.DataAccessLayer
	Issuer                *jwtx.Issuer
	RefreshTTL            time.Duration
	ReuseDetectionEnabled bool
	ClaimsHook            ClaimsHook
}

type refreshService struct {
	deps RefreshDeps
}

// NewRefreshService creates a new refresh service.
func NewRefreshService(deps RefreshDeps) RefreshService {
	if deps.ClaimsHook == nil {
		deps.ClaimsHook = NoOpClaimsHook{}
	}
	return &refreshService{deps: deps}
}

// Refresh errors
var (
	ErrMissingRefreshFields = errors.New("missing required fields")
	ErrInvalidRefreshToken  = errors.New("invalid or expired refresh token")
	ErrRefreshTokenRevoked  = errors.New("refresh token revoked")
	ErrRefreshTokenReuse    = errors.New("refresh token reuse detected")
	ErrClientMismatch       = errors.New("client_id mismatch")
	ErrRefreshUserDisabled  = errors.New("user disabled")
	ErrRefreshIssueFailed   = errors.New("failed to issue tokens")
)

func (s *refreshService) Refresh(ctx context.Context, in dto.RefreshRequest, tenantSlug string) (*dto.RefreshResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.refresh"),
		logger.Op("Refresh"),
	)

	// Normalize inputs
	in.RefreshToken = strings.TrimSpace(in.RefreshToken)
	in.ClientID = strings.TrimSpace(in.ClientID)
	in.TenantID = strings.TrimSpace(in.TenantID)

	if in.RefreshToken == "" || in.ClientID == "" {
		return nil, ErrMissingRefreshFields
	}
	// Check if it's a JWT refresh token (stateless admin flow)
	// This takes precedence over tenant context checks for global admins
	if strings.Count(in.RefreshToken, ".") == 2 {
		result, err := s.refreshAdminJWT(ctx, in.RefreshToken, log)
		if err == nil {
			return result, nil
		}
		// If JWT validation failed, we only log it and continue if we have a tenant context
		// to try DB refresh. Otherwise, failure here + no tenant = failure.
		log.Debug("JWT refresh validation failed", logger.Err(err))
	}

	// Use provided tenant or fallback from context
	if tenantSlug == "" {
		tenantSlug = in.TenantID
	}
	if tenantSlug == "" {
		return nil, ErrMissingRefreshFields
	}

	// DB-based refresh flow
	return s.refreshFromDB(ctx, in, tenantSlug, log)
}

// refreshAdminJWT handles stateless JWT refresh for FS admins.
func (s *refreshService) refreshAdminJWT(ctx context.Context, tokenStr string, log *zap.Logger) (*dto.RefreshResult, error) {
	// Parse and verify JWT
	token, err := jwtv5.Parse(tokenStr, func(token *jwtv5.Token) (interface{}, error) {
		// 1. Validate Algorithm
		if token.Method.Alg() != jwtv5.SigningMethodEdDSA.Alg() {
			return nil, jwtv5.ErrTokenSignatureInvalid
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, jwtv5.ErrTokenUnverifiable
		}
		return s.deps.Issuer.Keys.PublicKeyByKID(kid)
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}

	claims, ok := token.Claims.(jwtv5.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	// 2. Validate Token Use
	use, _ := claims["token_use"].(string)
	if use != "refresh" {
		return nil, fmt.Errorf("not a refresh token")
	}

	// 3. Validate Issuer
	iss, _ := claims.GetIssuer()
	if iss != s.deps.Issuer.Iss {
		return nil, fmt.Errorf("issuer mismatch")
	}

	// 4. Validate Audience
	aud, _ := claims.GetAudience()
	// Using "admin" as expected audience for FS-admin tokens per user request context
	foundAud := false
	for _, a := range aud {
		if a == "admin" || a == "hellojohn:admin" {
			foundAud = true
			break
		}
	}
	if !foundAud {
		return nil, fmt.Errorf("aud mismatch: %v", aud)
	}

	userID, _ := claims.GetSubject()
	if userID == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	// Get signing key
	kid, priv, _, err := s.deps.Issuer.Keys.Active()
	if err != nil {
		return nil, fmt.Errorf("no signing key: %w", err)
	}

	now := time.Now().UTC()
	exp := now.Add(s.deps.Issuer.AccessTTL)

	// Build admin access token claims
	amr := []string{"pwd", "refresh"}
	grantedScopes := []string{"openid", "profile", "email"}
	std := map[string]any{
		"tid": "global",
		"amr": amr,
		"acr": "urn:hellojohn:loa:1",
		"scp": strings.Join(grantedScopes, " "),
	}

	// Minimal system claims for admin
	custom := helpers.PutSystemClaimsV2(map[string]any{}, s.deps.Issuer.Iss, map[string]any{"is_admin": true}, []string{"sys:admin"}, nil)

	atClaims := jwtv5.MapClaims{
		"iss": s.deps.Issuer.Iss,
		"sub": userID,
		"aud": "admin",
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
	}
	for k, v := range std {
		atClaims[k] = v
	}
	if custom != nil {
		atClaims["custom"] = custom
	}

	atToken := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, atClaims)
	atToken.Header["kid"] = kid
	atToken.Header["typ"] = "JWT"

	accessToken, err := atToken.SignedString(priv)
	if err != nil {
		return nil, fmt.Errorf("sign access failed: %w", err)
	}

	// Issue new refresh JWT (rotation)
	rtClaims := jwtv5.MapClaims{
		"iss":       s.deps.Issuer.Iss,
		"sub":       userID,
		"aud":       "admin",
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(s.deps.RefreshTTL).Unix(),
		"token_use": "refresh",
	}

	rtToken := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, rtClaims)
	rtToken.Header["kid"] = kid
	rtToken.Header["typ"] = "JWT"

	refreshToken, err := rtToken.SignedString(priv)
	if err != nil {
		return nil, fmt.Errorf("sign refresh failed: %w", err)
	}

	log.Info("admin JWT refresh successful")

	return &dto.RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(time.Until(exp).Seconds()),
	}, nil
}

// refreshFromDB handles stateful DB-based refresh for regular users.
func (s *refreshService) refreshFromDB(ctx context.Context, in dto.RefreshRequest, tenantSlug string, log *zap.Logger) (*dto.RefreshResult, error) {
	// Hash the refresh token (Base64URL encoding, aligned with login)
	hash := tokens.SHA256Base64URL(in.RefreshToken)

	// Get TDA for tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		log.Debug("tenant resolution failed", logger.Err(err))
		return nil, ErrInvalidClient
	}

	if err := tda.RequireDB(); err != nil {
		log.Debug("tenant DB not available", logger.Err(err))
		return nil, ErrNoDatabase
	}

	tenantID := tda.ID()
	log = log.With(logger.TenantSlug(tda.Slug()))

	// Find refresh token by hash
	rt, err := tda.Tokens().GetByHash(ctx, hash)
	if err != nil || rt == nil {
		log.Debug("refresh token not found")
		return nil, ErrInvalidRefreshToken
	}

	// Check if revoked or expired
	now := time.Now()
	if rt.RevokedAt != nil {
		if s.deps.ReuseDetectionEnabled {
			s.revokeRefreshFamily(ctx, tda, rt.ID, log)
			return nil, ErrRefreshTokenReuse
		}
		log.Debug("refresh token revoked")
		return nil, ErrRefreshTokenRevoked
	}
	if !now.Before(rt.ExpiresAt) {
		log.Debug("refresh token expired")
		return nil, ErrInvalidRefreshToken
	}

	// Validate client_id matches
	if !strings.EqualFold(in.ClientID, rt.ClientID) {
		log.Debug("client_id mismatch")
		return nil, ErrClientMismatch
	}

	// Prevent cross-tenant refresh (security hardening)
	if rt.TenantID != "" && rt.TenantID != tenantID {
		log.Warn("refresh token tenant mismatch",
			zap.String("req_tid", tenantID),
			zap.String("tok_tid", rt.TenantID),
		)
		return nil, ErrInvalidRefreshToken
	}

	// Check user is not disabled
	user, err := tda.Users().GetByID(ctx, rt.UserID)
	if err != nil {
		log.Debug("user not found", logger.Err(err))
		return nil, ErrInvalidRefreshToken
	}

	if helpers.IsUserDisabled(user) {
		log.Info("user disabled")
		return nil, ErrRefreshUserDisabled
	}

	log = log.With(logger.UserID(user.ID))

	tenantSettings := tda.Settings()
	tenantAccessTTL := tenantSettings.SessionLifetimeSeconds
	tenantRefreshTTL := tenantSettings.RefreshTokenLifetimeSeconds

	// Resolve client-scoped settings (scopes + TTL overrides).
	var (
		grantedScopes    []string
		clientAccessTTL  int
		clientRefreshTTL int
	)
	if client, err := tda.Clients().Get(ctx, rt.ClientID); err == nil && client != nil {
		grantedScopes = client.Scopes
		clientAccessTTL = client.AccessTokenTTL
		clientRefreshTTL = client.RefreshTokenTTL
	} else {
		grantedScopes = []string{"openid"}
	}

	accessTTLSeconds := effectiveTTLSeconds(clientAccessTTL, tenantAccessTTL, s.deps.Issuer.AccessTTL)
	refreshTTLSeconds := effectiveTTLSeconds(clientRefreshTTL, tenantRefreshTTL, s.deps.RefreshTTL)

	// Build claims
	amr := []string{"refresh"}
	std := map[string]any{
		"tid": tenantID,
		"amr": amr,
		"scp": strings.Join(grantedScopes, " "),
	}
	custom := map[string]any{}

	// Apply claims hook
	std, custom = s.deps.ClaimsHook.ApplyAccess(ctx, tenantID, in.ClientID, user.ID, grantedScopes, amr, std, custom)

	// Resolve effective issuer
	effIss := jwtx.ResolveIssuer(
		s.deps.Issuer.Iss,
		string(tda.Settings().IssuerMode),
		tda.Slug(),
		tda.Settings().IssuerOverride,
	)

	// Add RBAC claims if supported
	custom = helpers.PutSystemClaimsV2(custom, effIss, user.Metadata, nil, nil)

	// Select signing key
	kid, priv, _, err := s.selectSigningKey(tda)
	if err != nil {
		log.Error("failed to get signing key", logger.Err(err))
		return nil, ErrRefreshIssueFailed
	}

	nowUTC := time.Now().UTC()
	exp := nowUTC.Add(time.Duration(accessTTLSeconds) * time.Second)

	claims := jwtv5.MapClaims{
		"iss": effIss,
		"sub": user.ID,
		"aud": in.ClientID,
		"iat": nowUTC.Unix(),
		"nbf": nowUTC.Unix(),
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
		log.Error("failed to sign access token", logger.Err(err))
		return nil, ErrRefreshIssueFailed
	}

	// Create new refresh token (rotation)
	rawRefresh, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		log.Error("failed to generate refresh token", logger.Err(err))
		return nil, ErrRefreshIssueFailed
	}

	newHash := tokens.SHA256Base64URL(rawRefresh)
	ttlSeconds := refreshTTLSeconds

	tokenInput := repository.CreateRefreshTokenInput{
		TenantID:    tenantID,
		ClientID:    in.ClientID,
		UserID:      user.ID,
		TokenHash:   newHash,
		TTLSeconds:  ttlSeconds,
		RotatedFrom: &rt.ID,
	}

	if _, err := tda.Tokens().Create(ctx, tokenInput); err != nil {
		log.Error("failed to persist new refresh token", logger.Err(err))
		return nil, ErrRefreshIssueFailed
	}

	// Revoke old token (best effort)
	if err := tda.Tokens().Revoke(ctx, rt.ID); err != nil {
		log.Warn("failed to revoke old refresh token", logger.Err(err))
	}

	log.Info("refresh successful")

	return &dto.RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int64(time.Until(exp).Seconds()),
	}, nil
}

func (s *refreshService) selectSigningKey(tda store.TenantDataAccess) (kid string, priv any, pub any, err error) {
	settings := tda.Settings()
	if types.IssuerMode(settings.IssuerMode) == types.IssuerModePath {
		return s.deps.Issuer.Keys.ActiveForTenant(tda.Slug())
	}
	return s.deps.Issuer.Keys.Active()
}

func (s *refreshService) revokeRefreshFamily(ctx context.Context, tda store.TenantDataAccess, tokenID string, log *zap.Logger) {
	if tda == nil || tokenID == "" {
		return
	}

	rootID, err := tda.Tokens().GetFamilyRoot(ctx, tokenID)
	if err != nil {
		log.Warn("failed to resolve refresh family root", logger.Err(err))
		return
	}

	if err := tda.Tokens().RevokeFamily(ctx, rootID); err != nil {
		log.Warn("failed to revoke refresh family", logger.Err(err), zap.String("family_root_id", rootID))
		return
	}

	log.Warn("refresh family revoked due to token reuse", zap.String("family_root_id", rootID))
}

func effectiveTTLSeconds(clientTTL int, tenantTTL int, globalTTL time.Duration) int {
	if clientTTL > 0 {
		return clientTTL
	}
	if tenantTTL > 0 {
		return tenantTTL
	}
	seconds := int(globalTTL.Seconds())
	if seconds <= 0 {
		return 1
	}
	return seconds
}
