package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

const invitationTTL = 7 * 24 * time.Hour

// InvitationService administra invitaciones desde el panel admin.
type InvitationService interface {
	Create(ctx context.Context, tenantSlug, adminUserID string, req dto.CreateInvitationRequest) (*dto.InvitationResponse, string, error)
	List(ctx context.Context, tenantSlug string, status *string, limit, offset int) (*dto.ListInvitationsResponse, error)
	Revoke(ctx context.Context, tenantSlug, id string) error
}

// InvitationDeps contiene dependencias del servicio de invitaciones admin.
type InvitationDeps struct {
	DAL store.DataAccessLayer
}

type invitationService struct {
	deps InvitationDeps
}

var (
	ErrInvalidInvitationEmail    = errors.New("invitation: email is required")
	ErrInvitationAlreadyHandled  = errors.New("invitation: already accepted, expired or revoked")
	ErrInvitationInvalidStatus   = errors.New("invitation: invalid status filter")
	ErrInvitationAdminIDRequired = errors.New("invitation: admin user id is required")
)

// NewInvitationService crea un InvitationService.
func NewInvitationService(deps InvitationDeps) InvitationService {
	return &invitationService{deps: deps}
}

func (s *invitationService) Create(ctx context.Context, tenantSlug, adminUserID string, req dto.CreateInvitationRequest) (*dto.InvitationResponse, string, error) {
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" {
		return nil, "", ErrInvalidInvitationEmail
	}
	if strings.TrimSpace(adminUserID) == "" {
		return nil, "", ErrInvitationAdminIDRequired
	}

	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, "", err
	}
	if err := tda.RequireDB(); err != nil {
		return nil, "", err
	}

	rawToken, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("generate invitation token: %w", err)
	}
	tokenHash := tokens.SHA256Base64URL(rawToken)

	roles := req.Roles
	if roles == nil {
		roles = []string{}
	}

	inv, err := tda.Invitations().Create(ctx, repository.CreateInvitationInput{
		TenantID:    tda.ID(),
		Email:       email,
		TokenHash:   tokenHash,
		InvitedByID: adminUserID,
		Roles:       roles,
		ExpiresAt:   time.Now().UTC().Add(invitationTTL),
	})
	if err != nil {
		return nil, "", err
	}

	return mapInvitationToDTO(inv), rawToken, nil
}

func (s *invitationService) List(ctx context.Context, tenantSlug string, status *string, limit, offset int) (*dto.ListInvitationsResponse, error) {
	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	var statusFilter *repository.InvitationStatus
	if status != nil {
		sanitized := strings.TrimSpace(strings.ToLower(*status))
		switch repository.InvitationStatus(sanitized) {
		case repository.InvitationPending, repository.InvitationAccepted, repository.InvitationExpired, repository.InvitationRevoked:
			v := repository.InvitationStatus(sanitized)
			statusFilter = &v
		default:
			return nil, ErrInvitationInvalidStatus
		}
	}

	invs, err := tda.Invitations().List(ctx, tda.ID(), statusFilter, limit, offset)
	if err != nil {
		return nil, err
	}

	resp := &dto.ListInvitationsResponse{
		Invitations: make([]dto.InvitationResponse, 0, len(invs)),
		Total:       len(invs),
		Limit:       limit,
		Offset:      offset,
	}
	for i := range invs {
		resp.Invitations = append(resp.Invitations, *mapInvitationToDTO(&invs[i]))
	}
	return resp, nil
}

func (s *invitationService) Revoke(ctx context.Context, tenantSlug, id string) error {
	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return err
	}
	if err := tda.RequireDB(); err != nil {
		return err
	}

	if err := tda.Invitations().UpdateStatus(ctx, tda.ID(), id, repository.InvitationRevoked, nil); err != nil {
		if errors.Is(err, repository.ErrInvitationNotPending) {
			return ErrInvitationAlreadyHandled
		}
		return err
	}
	return nil
}

func mapInvitationToDTO(inv *repository.Invitation) *dto.InvitationResponse {
	out := &dto.InvitationResponse{
		ID:        inv.ID,
		Email:     inv.Email,
		Status:    string(inv.Status),
		Roles:     inv.Roles,
		ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
		CreatedAt: inv.CreatedAt.Format(time.RFC3339),
	}
	if inv.AcceptedAt != nil {
		v := inv.AcceptedAt.Format(time.RFC3339)
		out.AcceptedAt = &v
	}
	return out
}

