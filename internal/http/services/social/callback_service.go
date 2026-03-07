package social

import (
	"context"
	"errors"
)

// CallbackService handles the callback phase of social login.
type CallbackService interface {
	// Callback processes the OAuth callback and returns redirect URL or token response.
	Callback(ctx context.Context, req CallbackRequest) (*CallbackResult, error)
}

// CallbackRequest contains the parameters for processing callback.
type CallbackRequest struct {
	Provider string
	State    string
	Code     string
	BaseURL  string
	// UserPayload contains optional provider-specific user payload from callback.
	// Apple sends "user" only on first authorization when using response_mode=form_post.
	UserPayload string
}

// CallbackResult contains the result of callback processing.
type CallbackResult struct {
	// If RedirectURL is set, controller should redirect
	RedirectURL string
	// If JSONResponse is set, controller should return JSON
	JSONResponse []byte
}

// Errors for callback service.
var (
	ErrCallbackMissingState          = errors.New("missing state")
	ErrCallbackMissingCode           = errors.New("missing code")
	ErrCallbackInvalidState          = errors.New("invalid state")
	ErrCallbackProviderMismatch      = errors.New("provider mismatch")
	ErrCallbackProviderUnknown       = errors.New("unknown provider")
	ErrCallbackProviderDisabled      = errors.New("provider not enabled")
	ErrCallbackOIDCExchangeFailed    = errors.New("OIDC code exchange failed")
	ErrCallbackIDTokenInvalid        = errors.New("ID token invalid")
	ErrCallbackEmailMissing          = errors.New("email missing in ID token")
	ErrCallbackProvisionFailed       = errors.New("user provisioning failed")
	ErrCallbackTokenIssueFailed      = errors.New("token issuance failed")
	ErrCallbackInvalidClient         = errors.New("invalid client_id")
	ErrCallbackInvalidRedirect       = errors.New("invalid redirect_uri")
	ErrCallbackProviderMisconfigured = errors.New("provider misconfigured")
)
