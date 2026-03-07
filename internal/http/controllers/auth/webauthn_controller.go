package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
)

const maxWebAuthnBodySize = 2 * 1024 * 1024 // 2MB

type webAuthnBeginRegistrationRequest struct {
	TenantID string `json:"tenant_id"`
}

type webAuthnFinishRegistrationRequest struct {
	TenantID  string          `json:"tenant_id"`
	SessionID string          `json:"session_id"`
	Name      string          `json:"name"`
	Response  json.RawMessage `json:"response"`
}

type webAuthnBeginLoginRequest struct {
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
}

type webAuthnFinishLoginRequest struct {
	TenantID  string          `json:"tenant_id"`
	SessionID string          `json:"session_id"`
	Response  json.RawMessage `json:"response"`
}

// WebAuthnController maneja endpoints de passkeys/webAuthn.
type WebAuthnController struct {
	service svc.WebAuthnAuthService
}

// NewWebAuthnController crea WebAuthnController.
func NewWebAuthnController(service svc.WebAuthnAuthService) *WebAuthnController {
	return &WebAuthnController{service: service}
}

// BeginRegistration maneja POST /v2/auth/webauthn/register/begin.
// Requiere usuario autenticado.
func (c *WebAuthnController) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	ctx := r.Context()
	claims := mw.GetClaims(ctx)
	userID := mw.ClaimString(claims, "sub")
	if strings.TrimSpace(userID) == "" {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodySize)
	defer r.Body.Close()

	var req webAuthnBeginRegistrationRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	tenantSlug := resolveTenantSlug(r, req.TenantID)
	optionsJSON, sessionID, err := c.service.BeginRegistration(ctx, tenantSlug, userID)
	if err != nil {
		c.writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"options":    json.RawMessage(optionsJSON),
		"session_id": sessionID,
	})
}

// FinishRegistration maneja POST /v2/auth/webauthn/register/finish.
// Requiere usuario autenticado.
func (c *WebAuthnController) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodySize)
	defer r.Body.Close()

	var req webAuthnFinishRegistrationRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	tenantSlug := resolveTenantSlug(r, req.TenantID)
	if err := c.service.FinishRegistration(ctx, tenantSlug, req.SessionID, req.Response, req.Name); err != nil {
		c.writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]bool{"registered": true})
}

// BeginLogin maneja POST /v2/auth/webauthn/login/begin.
func (c *WebAuthnController) BeginLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodySize)
	defer r.Body.Close()

	var req webAuthnBeginLoginRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	tenantSlug := resolveTenantSlug(r, req.TenantID)
	optionsJSON, sessionID, err := c.service.BeginLogin(ctx, tenantSlug, req.Email)
	if err != nil {
		c.writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"options":    json.RawMessage(optionsJSON),
		"session_id": sessionID,
	})
}

// FinishLogin maneja POST /v2/auth/webauthn/login/finish.
func (c *WebAuthnController) FinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodySize)
	defer r.Body.Close()

	var req webAuthnFinishLoginRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	tenantSlug := resolveTenantSlug(r, req.TenantID)
	result, err := c.service.FinishLogin(ctx, tenantSlug, req.SessionID, req.Response)
	if err != nil {
		c.writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(dto.LoginResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
	})
}

func (c *WebAuthnController) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrWebAuthnTenantRequired),
		errors.Is(err, svc.ErrWebAuthnUserRequired),
		errors.Is(err, svc.ErrWebAuthnEmailRequired),
		errors.Is(err, svc.ErrWebAuthnSessionRequired),
		errors.Is(err, svc.ErrWebAuthnResponseRequired),
		errors.Is(err, svc.ErrWebAuthnInvalidSessionID):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrWebAuthnUserNotFound),
		errors.Is(err, svc.ErrWebAuthnNoCredentials):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrWebAuthnChallengeExpired):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrWebAuthnCredentialCloneWarning):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrWebAuthnNoClient),
		errors.Is(err, repository.ErrNoDatabase):
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrWebAuthnRPIDRequired),
		errors.Is(err, svc.ErrWebAuthnCacheUnavailable):
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrWebAuthnTokenIssueFailed):
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail(err.Error()))
	default:
		httperrors.WriteError(w, httperrors.FromError(err))
	}
}

func resolveTenantSlug(r *http.Request, fromBody string) string {
	tenantSlug := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantSlug == "" {
		tenantSlug = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantSlug == "" {
		tenantSlug = strings.TrimSpace(fromBody)
	}
	return tenantSlug
}
