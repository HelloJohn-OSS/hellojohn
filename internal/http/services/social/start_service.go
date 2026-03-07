package social

import (
	"context"
	"errors"
)

// StartService handles the start phase of social login.
type StartService interface {
	// Start initiates social login flow and returns the redirect URL.
	Start(ctx context.Context, req StartRequest) (*StartResult, error)
}

// StartRequest contains the parameters for starting social login.
type StartRequest struct {
	Provider    string
	TenantSlug  string
	ClientID    string
	RedirectURI string
	BaseURL     string // Base URL for constructing callback URL
}

// StartResult contains the result of starting social login.
type StartResult struct {
	RedirectURL string
}

// Errors for start service.
var (
	ErrStartMissingTenant         = errors.New("missing tenant")
	ErrStartMissingClientID       = errors.New("missing client_id")
	ErrStartProviderUnknown       = errors.New("unknown provider")
	ErrStartProviderDisabled      = errors.New("provider not enabled")
	ErrStartAuthURLFailed         = errors.New("failed to generate auth URL")
	ErrStartInvalidClient         = errors.New("invalid client_id")
	ErrStartProviderMisconfigured = errors.New("provider misconfigured")
	ErrStartInvalidRedirect       = errors.New("invalid redirect_uri")
	ErrStartRedirectNotAllowed    = errors.New("redirect_uri not allowed")
)
