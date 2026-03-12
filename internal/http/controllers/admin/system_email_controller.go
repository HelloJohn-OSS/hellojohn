package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// SystemEmailController handles /v2/admin/system/email endpoints.
type SystemEmailController struct {
	service svc.SystemEmailService
}

// NewSystemEmailController creates a new SystemEmailController.
func NewSystemEmailController(service svc.SystemEmailService) *SystemEmailController {
	return &SystemEmailController{service: service}
}

func (c *SystemEmailController) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("SystemEmail.Get"))

	resp, err := c.service.Get(ctx)
	if err != nil {
		log.Error("get system email provider failed", logger.Err(err))
		httperrors.WriteError(w, mapSystemEmailError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (c *SystemEmailController) Put(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("SystemEmail.Put"))

	var req dto.SystemEmailProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	actor := "system"
	if claims := mw.GetAdminClaims(ctx); claims != nil {
		if strings.TrimSpace(claims.Email) != "" {
			actor = strings.TrimSpace(claims.Email)
		} else if strings.TrimSpace(claims.AdminID) != "" {
			actor = strings.TrimSpace(claims.AdminID)
		}
	}

	resp, err := c.service.Set(ctx, req, actor)
	if err != nil {
		log.Error("set system email provider failed", logger.Err(err))
		httperrors.WriteError(w, mapSystemEmailError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (c *SystemEmailController) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("SystemEmail.Delete"))

	actor := "system"
	if claims := mw.GetAdminClaims(ctx); claims != nil {
		if strings.TrimSpace(claims.Email) != "" {
			actor = strings.TrimSpace(claims.Email)
		} else if strings.TrimSpace(claims.AdminID) != "" {
			actor = strings.TrimSpace(claims.AdminID)
		}
	}

	if err := c.service.Delete(ctx, actor); err != nil {
		log.Error("delete system email provider failed", logger.Err(err))
		httperrors.WriteError(w, mapSystemEmailError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (c *SystemEmailController) Test(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("SystemEmail.Test"))

	var req dto.SystemEmailTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	resp, err := c.service.Test(ctx, req)
	if err != nil {
		log.Error("system email test failed", logger.Err(err))
		httperrors.WriteError(w, mapSystemEmailError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func mapSystemEmailError(err error) *httperrors.AppError {
	if err == nil {
		return httperrors.ErrInternalServerError
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))

	switch {
	case strings.Contains(msg, "required"), strings.Contains(msg, "invalid"):
		return httperrors.ErrBadRequest.WithDetail(err.Error())
	case strings.Contains(msg, "not available"):
		return httperrors.ErrServiceUnavailable.WithDetail(err.Error())
	case strings.Contains(msg, "not configured"):
		return httperrors.ErrBadRequest.WithDetail(err.Error())
	default:
		return httperrors.ErrInternalServerError.WithCause(err)
	}
}
