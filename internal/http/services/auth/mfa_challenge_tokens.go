package auth

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/domain/types"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func resolveMFAChallengeFromToken(ctx context.Context, dal store.DataAccessLayer, tenantSlug, token string) (store.TenantDataAccess, cache.Client, string, mfaChallenge, error) {
	key := "mfa:token:" + strings.TrimSpace(token)

	tda, err := dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, nil, "", mfaChallenge{}, ErrMFATenantMismatch
	}

	cacheRepo := tda.Cache()
	payload, err := cacheRepo.Get(ctx, key)
	if err != nil {
		if cache.IsNotFound(err) {
			return nil, nil, "", mfaChallenge{}, ErrMFATokenNotFound
		}
		return nil, nil, "", mfaChallenge{}, ErrMFAStoreFailed
	}

	var challenge mfaChallenge
	if err := json.Unmarshal([]byte(payload), &challenge); err != nil {
		return nil, nil, "", mfaChallenge{}, ErrMFATokenInvalid
	}
	if tda.ID() != challenge.TenantID {
		return nil, nil, "", mfaChallenge{}, ErrMFATenantMismatch
	}
	return tda, cacheRepo, key, challenge, nil
}

func issueMFAChallengeTokens(ctx context.Context, issuer *jwtx.Issuer, tda store.TenantDataAccess, challenge mfaChallenge, refreshTTL time.Duration, claimsHook ClaimsHook) (string, string, int64, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.challenge.issue_tokens"))

	tokenRepo := tda.Tokens()
	if tokenRepo == nil {
		return "", "", 0, ErrMFANotSupported
	}

	if issuer == nil {
		return "", "", 0, ErrMFANotInitialized
	}

	amr := append(challenge.AMRBase, "mfa")
	acr := "urn:hellojohn:loa:2"

	std := map[string]any{
		"tid": challenge.TenantID,
		"amr": amr,
		"acr": acr,
		"scp": strings.Join(challenge.Scope, " "),
	}
	custom := map[string]any{}
	if claimsHook != nil {
		std, custom = claimsHook.ApplyAccess(ctx, challenge.TenantID, challenge.ClientID, challenge.UserID, challenge.Scope, amr, std, custom)
	}

	settings := tda.Settings()
	effIss := jwtx.ResolveIssuer(
		issuer.Iss,
		string(settings.IssuerMode),
		tda.Slug(),
		settings.IssuerOverride,
	)

	var (
		kid  string
		priv any
		err  error
	)
	if types.IssuerMode(settings.IssuerMode) == types.IssuerModePath {
		kid, priv, _, err = issuer.Keys.ActiveForTenant(tda.Slug())
	} else {
		kid, priv, _, err = issuer.Keys.Active()
	}
	if err != nil {
		log.Error("failed to select signing key", logger.Err(err))
		return "", "", 0, ErrMFACryptoFailed
	}

	now := time.Now().UTC()
	exp := now.Add(issuer.AccessTTL)
	claims := jwtv5.MapClaims{
		"iss": effIss,
		"sub": challenge.UserID,
		"aud": challenge.ClientID,
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

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"

	accessToken, err := token.SignedString(priv)
	if err != nil {
		log.Error("failed to sign access token", logger.Err(err))
		return "", "", 0, ErrMFACryptoFailed
	}

	rawRT, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		return "", "", 0, ErrMFACryptoFailed
	}
	rtHash := tokens.SHA256Base64URL(rawRT)
	if _, err := tokenRepo.Create(ctx, repository.CreateRefreshTokenInput{
		TenantID:   challenge.TenantID,
		ClientID:   challenge.ClientID,
		UserID:     challenge.UserID,
		TokenHash:  rtHash,
		TTLSeconds: int(refreshTTL.Seconds()),
	}); err != nil {
		log.Error("failed to persist refresh token", logger.Err(err))
		return "", "", 0, ErrMFAStoreFailed
	}

	return accessToken, rawRT, int64(issuer.AccessTTL.Seconds()), nil
}
