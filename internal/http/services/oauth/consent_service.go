package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/oauth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Errors
var (
	ErrConsentMissingToken = errors.New("consent_token required")
	ErrConsentNotFound     = errors.New("invalid or expired consent_token")
	ErrConsentStoreFailed  = errors.New("failed to store consent")
	ErrConsentCodeFailed   = errors.New("failed to generate auth code")
)

// ConsentService handles consent acceptance logic.
type ConsentService interface {
	Accept(ctx context.Context, req dto.ConsentAcceptRequest) (*dto.AuthCodeRedirect, error)
	// GetInfo retrieves consent challenge info with scope DisplayNames for consent screen.
	// ISS-05-03: DisplayName in Consent Screen
	GetInfo(ctx context.Context, token string) (*dto.ConsentInfoResponse, error)
}

// ConsentDeps dependencies.
type ConsentDeps struct {
	DAL          store.DataAccessLayer
	Cache        CacheClient
	ControlPlane controlplane.Service
}

type consentService struct {
	dal   store.DataAccessLayer
	cache CacheClient
	cp    controlplane.Service
}

func NewConsentService(d ConsentDeps) ConsentService {
	return &consentService{
		dal:   d.DAL,
		cache: d.Cache,
		cp:    d.ControlPlane,
	}
}

// Accept processes the user's decision on the consent screen.
func (s *consentService) Accept(ctx context.Context, req dto.ConsentAcceptRequest) (*dto.AuthCodeRedirect, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("oauth.consent.accept"))

	// 1. Validate Input
	if strings.TrimSpace(req.Token) == "" {
		return nil, ErrConsentMissingToken
	}

	// 2. Consume Token (One-Shot)
	key := "consent:token:" + strings.TrimSpace(req.Token)
	raw, ok := s.cache.Get(key)
	if !ok {
		return nil, ErrConsentNotFound
	}
	s.cache.Delete(key)

	var payload dto.ConsentChallenge
	if err := json.Unmarshal(raw, &payload); err != nil {
		log.Error("consent payload corrupted", logger.Err(err))
		return nil, ErrConsentNotFound
	}

	// Double check expiry
	if time.Now().After(payload.ExpiresAt) {
		return nil, ErrConsentNotFound
	}

	// 3. Handle Rejection
	if !req.Approve {
		loc := buildRedirect(payload.RedirectURI, map[string]string{
			"error": "access_denied",
			"state": payload.State,
		})
		return &dto.AuthCodeRedirect{URL: loc}, nil
	}

	// 4. Handle Approval
	// Resolve Tenant Data Access
	// Note: payload.TenantID refers to tenant slug in V2 context (from Authorize service)
	tda, err := s.dal.ForTenant(ctx, payload.TenantID)
	if err != nil {
		log.Error("failed to resolve tenant for consent", logger.Err(err), logger.String("tid", payload.TenantID))
		return nil, ErrConsentStoreFailed
	}

	// Persist Consent using repository
	// tda.ID() provee el UUID resuelto por ForTenant — no pasar payload.TenantID (puede ser slug)
	_, err = tda.Consents().Upsert(ctx, tda.ID(), payload.UserID, payload.ClientID, payload.RequestedScopes)
	if err != nil {
		log.Error("failed to upsert consent", logger.Err(err))
		return nil, ErrConsentStoreFailed
	}

	// 5. Issue Code
	code, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		log.Error("failed to generate code", logger.Err(err))
		return nil, ErrConsentCodeFailed
	}

	authPayload := AuthCodePayload{
		UserID:          payload.UserID,
		ClientID:        payload.ClientID,
		TenantID:        payload.TenantID,
		RedirectURI:     payload.RedirectURI,
		Scope:           strings.Join(payload.RequestedScopes, " "),
		Nonce:           payload.Nonce,
		CodeChallenge:   payload.CodeChallenge,
		ChallengeMethod: payload.CodeChallengeMethod,
		AMR:             payload.AMR,
		ExpiresAt:       time.Now().Add(10 * time.Minute), // Match V2 TTL
	}

	authBytes, _ := json.Marshal(authPayload)

	// Note: Store hashed code (hardening)
	// V2 TokenService expects "code:<hash>" (or "code:<code>" fallback)
	codeHash := tokens.SHA256Base64URL(code)
	s.cache.Set("code:"+codeHash, authBytes, 10*time.Minute)

	// 6. Return Redirect
	loc := buildRedirect(payload.RedirectURI, map[string]string{
		"code":  code,
		"state": payload.State,
	})

	return &dto.AuthCodeRedirect{URL: loc}, nil
}

// GetInfo retrieves consent info with scope DisplayNames for consent screen.
// ISS-05-03: DisplayName in Consent Screen
func (s *consentService) GetInfo(ctx context.Context, token string) (*dto.ConsentInfoResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("oauth.consent.getInfo"))

	// 1. Validate Token
	if strings.TrimSpace(token) == "" {
		return nil, ErrConsentMissingToken
	}

	// 2. Fetch Token (don't delete - just peek)
	key := "consent:token:" + strings.TrimSpace(token)
	raw, ok := s.cache.Get(key)
	if !ok {
		return nil, ErrConsentNotFound
	}

	var payload dto.ConsentChallenge
	if err := json.Unmarshal(raw, &payload); err != nil {
		log.Error("consent payload corrupted", logger.Err(err))
		return nil, ErrConsentNotFound
	}

	// Double check expiry
	if time.Now().After(payload.ExpiresAt) {
		return nil, ErrConsentNotFound
	}

	// 3. Resolve tenant data access
	tda, err := s.dal.ForTenant(ctx, payload.TenantID)
	if err != nil {
		log.Error("failed to resolve tenant", logger.Err(err), logger.String("tid", payload.TenantID))
		return nil, ErrConsentNotFound
	}

	// 4. Build scope details with DisplayNames
	scopeDetails := make([]dto.ScopeDetail, 0, len(payload.RequestedScopes))
	for _, scopeName := range payload.RequestedScopes {
		scope, err := tda.Scopes().GetByName(ctx, scopeName)
		if err != nil {
			// If scope not found, use name as display name
			scopeDetails = append(scopeDetails, dto.ScopeDetail{
				Name:        scopeName,
				DisplayName: scopeName,
			})
			continue
		}

		detail := dto.ScopeDetail{
			Name:        scope.Name,
			DisplayName: scope.DisplayName,
			Description: scope.Description,
		}

		// Fallback: if no display_name, use name
		if detail.DisplayName == "" {
			detail.DisplayName = scope.Name
		}

		scopeDetails = append(scopeDetails, detail)
	}

	// 5. Get client name (optional enhancement)
	var clientName string
	if s.cp != nil {
		client, err := s.cp.GetClient(ctx, payload.TenantID, payload.ClientID)
		if err == nil && client != nil {
			clientName = client.Name
		}
	}

	return &dto.ConsentInfoResponse{
		ClientID:    payload.ClientID,
		ClientName:  clientName,
		Scopes:      scopeDetails,
		RedirectURI: payload.RedirectURI,
	}, nil
}

// buildRedirect constructs the URL safely.
func buildRedirect(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base // fallback
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
