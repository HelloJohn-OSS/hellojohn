package admin

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	helpers "github.com/dropDatabas3/hellojohn/internal/http/helpers"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
)

// UsageController expone métricas de uso de tenants.
type UsageController struct {
	service svc.UsageService
}

// NewUsageController crea un UsageController.
// service puede ser nil (sin global DB) — los handlers retornan 503.
func NewUsageController(service svc.UsageService) *UsageController {
	return &UsageController{service: service}
}

// GetTenantUsage handles GET /v2/admin/tenants/{tenant_id}/usage?month=YYYY-MM
func (c *UsageController) GetTenantUsage(w http.ResponseWriter, r *http.Request) {
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("usage metrics require a global database"))
		return
	}
	tenantID := r.PathValue("tenant_id")
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing tenant_id"))
		return
	}

	month := resolveMonth(r.URL.Query().Get("month"))

	stats, err := c.service.GetTenantUsage(r.Context(), tenantID, month)
	if err != nil {
		if errors.Is(err, svc.ErrUsageNotAvailable) {
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail(err.Error()))
			return
		}
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		return
	}

	helpers.WriteJSON(w, http.StatusOK, stats)
}

// GetSummary handles GET /v2/admin/usage/summary?month=YYYY-MM&limit=N
func (c *UsageController) GetSummary(w http.ResponseWriter, r *http.Request) {
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("usage metrics require a global database"))
		return
	}

	month := resolveMonth(r.URL.Query().Get("month"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 10
	}

	tenants, err := c.service.ListTopTenants(r.Context(), month, limit)
	if err != nil {
		if errors.Is(err, svc.ErrUsageNotAvailable) {
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail(err.Error()))
			return
		}
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		return
	}

	helpers.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"month":   month.Format("2006-01"),
		"tenants": tenants,
	})
}

// GetHistory handles GET /v2/admin/tenants/{tenant_id}/usage/history?months=N
func (c *UsageController) GetHistory(w http.ResponseWriter, r *http.Request) {
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("usage metrics require a global database"))
		return
	}
	tenantID := r.PathValue("tenant_id")
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing tenant_id"))
		return
	}

	months, _ := strconv.Atoi(r.URL.Query().Get("months"))
	if months <= 0 {
		months = 6
	}

	history, err := c.service.GetUsageHistory(r.Context(), tenantID, months)
	if err != nil {
		if errors.Is(err, svc.ErrUsageNotAvailable) {
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail(err.Error()))
			return
		}
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		return
	}

	helpers.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id": tenantID,
		"months":    months,
		"history":   history,
	})
}

// resolveMonth parsea un mes YYYY-MM del query string, o usa el mes actual.
func resolveMonth(raw string) time.Time {
	if raw != "" {
		if t, err := time.Parse("2006-01", raw); err == nil {
			return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		}
	}
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
}
