package repository

import (
	"context"
	"errors"
	"time"
)

// InvitationStatus representa el estado de una invitacion.
type InvitationStatus string

const (
	InvitationPending  InvitationStatus = "pending"
	InvitationAccepted InvitationStatus = "accepted"
	InvitationExpired  InvitationStatus = "expired"
	InvitationRevoked  InvitationStatus = "revoked"
)

// Invitation representa una invitacion de onboarding.
type Invitation struct {
	ID          string
	TenantID    string
	Email       string
	TokenHash   string
	Status      InvitationStatus
	InvitedByID string
	Roles       []string
	ExpiresAt   time.Time
	AcceptedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreateInvitationInput es el input para crear una invitacion.
type CreateInvitationInput struct {
	TenantID    string
	Email       string
	TokenHash   string
	InvitedByID string
	Roles       []string
	ExpiresAt   time.Time
}

// InvitationRepository define el contrato de persistencia para invitaciones.
type InvitationRepository interface {
	Create(ctx context.Context, in CreateInvitationInput) (*Invitation, error)
	GetByTokenHash(ctx context.Context, tenantID, hash string) (*Invitation, error)
	GetByID(ctx context.Context, tenantID, id string) (*Invitation, error)
	List(ctx context.Context, tenantID string, status *InvitationStatus, limit, offset int) ([]Invitation, error)
	UpdateStatus(ctx context.Context, tenantID, id string, newStatus InvitationStatus, acceptedAt *time.Time) error
	Delete(ctx context.Context, tenantID, id string) error
}

var ErrInvitationNotPending = errors.New("invitation is not in pending state")
