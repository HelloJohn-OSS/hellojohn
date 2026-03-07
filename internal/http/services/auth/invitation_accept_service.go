package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/domain/types"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/security/password"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// InvitationAcceptService maneja la aceptacion de invitaciones.
type InvitationAcceptService interface {
	Accept(ctx context.Context, tenantSlug string, req dto.AcceptInvitationRequest) (*dto.AcceptInvitationResponse, error)
}

// InvitationAcceptDeps contiene dependencias del accept service.
type InvitationAcceptDeps struct {
	DAL        store.DataAccessLayer
	Issuer     *jwtx.Issuer
	RefreshTTL time.Duration
	ClaimsHook ClaimsHook
}

type invitationAcceptService struct {
	deps InvitationAcceptDeps
}

// Errores de invitaciones (accept flow).
var (
	ErrInvitationTenantRequired   = errors.New("invitation: tenant is required")
	ErrInvitationTokenRequired    = errors.New("invitation: token is required")
	ErrInvitationPasswordRequired = errors.New("invitation: password is required")
	ErrInvitationInvalid          = errors.New("invitation: invalid or not found")
	ErrInvitationAlreadyUsed      = errors.New("invitation: already accepted or revoked")
	ErrInvitationExpired          = errors.New("invitation: expired")
	ErrInvitationCreateFailed     = errors.New("invitation: failed to create user")
	ErrInvitationTokenIssueFailed = errors.New("invitation: failed to issue tokens")
	ErrInvitationNoClient         = errors.New("invitation: no available client for tenant")
)

// NewInvitationAcceptService crea un InvitationAcceptService.
func NewInvitationAcceptService(deps InvitationAcceptDeps) InvitationAcceptService {
	if deps.ClaimsHook == nil {
		deps.ClaimsHook = NoOpClaimsHook{}
	}
	return &invitationAcceptService{deps: deps}
}

func (s *invitationAcceptService) Accept(ctx context.Context, tenantSlug string, req dto.AcceptInvitationRequest) (*dto.AcceptInvitationResponse, error) {
	tenantSlug = strings.TrimSpace(tenantSlug)
	if tenantSlug == "" {
		return nil, ErrInvitationTenantRequired
	}
	if strings.TrimSpace(req.Token) == "" {
		return nil, ErrInvitationTokenRequired
	}
	if strings.TrimSpace(req.Password) == "" {
		return nil, ErrInvitationPasswordRequired
	}
	if s.deps.Issuer == nil {
		return nil, ErrInvitationTokenIssueFailed
	}

	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	tokenHash := tokens.SHA256Base64URL(req.Token)
	inv, err := tda.Invitations().GetByTokenHash(ctx, tda.ID(), tokenHash)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, ErrInvitationInvalid
	}

	switch inv.Status {
	case repository.InvitationPending:
		// ok
	case repository.InvitationExpired:
		return nil, ErrInvitationExpired
	default:
		return nil, ErrInvitationAlreadyUsed
	}

	now := time.Now().UTC()
	if now.After(inv.ExpiresAt) {
		expireErr := tda.Invitations().UpdateStatus(ctx, tda.ID(), inv.ID, repository.InvitationExpired, nil)
		if expireErr != nil && !errors.Is(expireErr, repository.ErrInvitationNotPending) {
			return nil, expireErr
		}
		if errors.Is(expireErr, repository.ErrInvitationNotPending) {
			return nil, ErrInvitationAlreadyUsed
		}
		return nil, ErrInvitationExpired
	}

	firstName := strings.TrimSpace(req.FirstName)
	lastName := strings.TrimSpace(req.LastName)
	name := strings.TrimSpace(strings.Join([]string{firstName, lastName}, " "))

	phc, err := password.Hash(password.Default, req.Password)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvitationCreateFailed, err)
	}

	user, _, err := tda.Users().Create(ctx, repository.CreateUserInput{
		TenantID:     tda.ID(),
		Email:        inv.Email,
		PasswordHash: phc,
		Name:         name,
		GivenName:    firstName,
		FamilyName:   lastName,
		Provider:     "password",
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvitationCreateFailed, err)
	}

	// Email ownership ya fue probada por token one-shot enviado al email invitado.
	_ = tda.Users().SetEmailVerified(ctx, user.ID, true)

	if rbac := tda.RBAC(); rbac != nil {
		for _, role := range inv.Roles {
			role = strings.TrimSpace(role)
			if role == "" {
				continue
			}
			// Best effort: si el rol no existe o ya esta asignado, el usuario puede continuar.
			_ = rbac.AssignRole(ctx, tda.ID(), user.ID, role)
		}
	}

	acceptedAt := time.Now().UTC()
	if err := tda.Invitations().UpdateStatus(ctx, tda.ID(), inv.ID, repository.InvitationAccepted, &acceptedAt); err != nil {
		if errors.Is(err, repository.ErrInvitationNotPending) {
			return nil, ErrInvitationAlreadyUsed
		}
		return nil, err
	}

	clientID, scopes, err := resolveInvitationClient(ctx, tda)
	if err != nil {
		return nil, err
	}

	accessToken, exp, err := s.issueAccessToken(ctx, tda, user.ID, clientID, scopes)
	if err != nil {
		return nil, err
	}

	rawRefresh, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		return nil, ErrInvitationTokenIssueFailed
	}
	refreshHash := tokens.SHA256Base64URL(rawRefresh)

	refreshTTL := s.deps.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = 24 * time.Hour
	}

	if _, err := tda.Tokens().Create(ctx, repository.CreateRefreshTokenInput{
		TenantID:   tda.ID(),
		ClientID:   clientID,
		UserID:     user.ID,
		TokenHash:  refreshHash,
		TTLSeconds: int(refreshTTL.Seconds()),
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvitationTokenIssueFailed, err)
	}

	return &dto.AcceptInvitationResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int64(time.Until(exp).Seconds()),
	}, nil
}

func resolveInvitationClient(ctx context.Context, tda store.TenantDataAccess) (string, []string, error) {
	clients, err := tda.Clients().List(ctx, "")
	if err != nil {
		return "", nil, err
	}
	if len(clients) == 0 {
		return "", nil, ErrInvitationNoClient
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

	return "", nil, ErrInvitationNoClient
}

func (s *invitationAcceptService) issueAccessToken(ctx context.Context, tda store.TenantDataAccess, userID, clientID string, scopes []string) (string, time.Time, error) {
	tenantID := tda.ID()
	amr := []string{"pwd"}
	std := map[string]any{
		"tid": tenantID,
		"amr": amr,
		"acr": "urn:hellojohn:loa:1",
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
		return "", time.Time{}, ErrInvitationTokenIssueFailed
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
		return "", time.Time{}, ErrInvitationTokenIssueFailed
	}
	return accessToken, exp, nil
}

func (s *invitationAcceptService) selectSigningKey(tda store.TenantDataAccess) (kid string, priv any, pub any, err error) {
	settings := tda.Settings()
	if types.IssuerMode(settings.IssuerMode) == types.IssuerModePath {
		return s.deps.Issuer.Keys.ActiveForTenant(tda.Slug())
	}
	return s.deps.Issuer.Keys.Active()
}
