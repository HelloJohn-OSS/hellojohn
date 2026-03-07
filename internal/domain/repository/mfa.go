package repository

import (
	"context"
	"time"
)

// MFATOTP representa la configuración TOTP de un usuario.
type MFATOTP struct {
	UserID          string
	SecretEncrypted string
	ConfirmedAt     *time.Time
	LastUsedAt      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// MFARepository define operaciones sobre MFA (TOTP y recovery codes).
type MFARepository interface {
	// ─── TOTP ───

	// UpsertTOTP crea o actualiza el secreto TOTP de un usuario.
	UpsertTOTP(ctx context.Context, userID, secretEnc string) error

	// ConfirmTOTP marca el TOTP como confirmado (usuario verificó con código).
	ConfirmTOTP(ctx context.Context, userID string) error

	// GetTOTP obtiene la configuración TOTP de un usuario.
	// Retorna ErrNotFound si no existe.
	GetTOTP(ctx context.Context, userID string) (*MFATOTP, error)

	// UpdateTOTPUsedAt actualiza el timestamp de último uso.
	UpdateTOTPUsedAt(ctx context.Context, userID string) error

	// DisableTOTP deshabilita el TOTP de un usuario.
	DisableTOTP(ctx context.Context, userID string) error

	// ─── Recovery Codes ───

	// SetRecoveryCodes reemplaza los recovery codes de un usuario.
	// Los codes deben estar hasheados antes de llamar.
	SetRecoveryCodes(ctx context.Context, userID string, hashes []string) error

	// DeleteRecoveryCodes elimina todos los recovery codes de un usuario.
	DeleteRecoveryCodes(ctx context.Context, userID string) error

	// UseRecoveryCode marca un recovery code como usado.
	// Retorna true si el code existía y fue marcado.
	UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error)

	// ─── Trusted Devices ───

	// AddTrustedDevice añade un dispositivo confiable (skip MFA).
	AddTrustedDevice(ctx context.Context, userID, deviceHash string, expiresAt time.Time) error

	// IsTrustedDevice verifica si un dispositivo es confiable y no expiró.
	IsTrustedDevice(ctx context.Context, userID, deviceHash string) (bool, error)
}
