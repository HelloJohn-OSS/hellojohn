package emailv2

import (
	"errors"
	"fmt"
)

var (
	ErrEmailAuth        = errors.New("email: authentication failed")
	ErrEmailRateLimited = errors.New("email: rate limited")
	ErrEmailRejected    = errors.New("email: message rejected")
	ErrEmailTemporary   = errors.New("email: temporary failure")
	ErrEmailPermanent   = errors.New("email: permanent failure")
	ErrEmailConfig      = errors.New("email: invalid configuration")

	ErrNoEmailConfigured        = errors.New("email: no provider configured")
	ErrSystemEmailNotConfigured = errors.New("system email: provider not configured")
)

// Legacy aliases (backward compatible errors).
var (
	ErrNoSMTPConfigured        = ErrNoEmailConfigured
	ErrSystemSMTPNotConfigured = ErrSystemEmailNotConfigured
)

// ProviderError normaliza errores de proveedores externos.
type ProviderError struct {
	Provider ProviderKind
	Category error
	Raw      error
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("%s [%s]: %v", e.Category, e.Provider, e.Raw)
}

func (e *ProviderError) Unwrap() error { return e.Category }

// WrapProviderError construye un ProviderError con categorÃ­a normalizada.
func WrapProviderError(p ProviderKind, category, raw error) error {
	return &ProviderError{Provider: p, Category: category, Raw: raw}
}
