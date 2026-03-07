package repository

import (
	"context"
	"time"
)

// WebAuthnCredential representa una passkey FIDO2 registrada.
type WebAuthnCredential struct {
	ID             string
	TenantID       string
	UserID         string
	CredentialID   []byte
	PublicKey      []byte
	AAGUID         string
	SignCount      uint32
	Transports     []string
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
	Name           string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

// WebAuthnRepository define operaciones para persistir credenciales passkey.
type WebAuthnRepository interface {
	Create(ctx context.Context, tenantID string, cred WebAuthnCredential) error
	GetByUserID(ctx context.Context, tenantID, userID string) ([]WebAuthnCredential, error)
	GetByCredentialID(ctx context.Context, tenantID string, credID []byte) (*WebAuthnCredential, error)
	UpdateSignCount(ctx context.Context, tenantID string, credID []byte, newCount uint32) error
	UpdateLastUsed(ctx context.Context, tenantID string, credID []byte) error
	Delete(ctx context.Context, tenantID, id string) error
}
