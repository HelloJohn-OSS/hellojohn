package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// MigrateController handles tenant migration from GDP to isolated DB.
type MigrateController struct {
	service svc.MigrateService
}

// NewMigrateController creates a new MigrateController.
func NewMigrateController(service svc.MigrateService) *MigrateController {
	return &MigrateController{service: service}
}

// MigrateToIsolatedDB handles POST /v2/admin/tenants/{tenant_id}/migrate-to-isolated-db
func (c *MigrateController) MigrateToIsolatedDB(w http.ResponseWriter, r *http.Request) {
	tenantRef := r.PathValue("tenant_id")
	if tenantRef == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing tenant_id"))
		return
	}
	// M-BACK-7: sanitize user-controlled tenantRef to prevent log injection.
	safeRef := strings.NewReplacer(`"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(tenantRef)

	var req dto.MigrateToIsolatedDBRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	if req.DSN == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("dsn field is required"))
		return
	}

	err := c.service.MigrateToIsolatedDB(r.Context(), tenantRef, req.DSN, req.Driver)
	if err != nil {
		switch {
		case errors.Is(err, svc.ErrMigrateTenantNotOnGDP):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant is not on the Global Data Plane"))
		case errors.Is(err, svc.ErrMigrateDSNEmpty):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("target DSN is required"))
		case errors.Is(err, svc.ErrMigrateAlreadyRunning):
			httperrors.WriteError(w, httperrors.ErrConflict.WithDetail("migration already in progress"))
		case errors.Is(err, svc.ErrMigrateETLNotImplemented):
			// Schema-only migration succeeded — data copy requires manual ETL.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if encErr := json.NewEncoder(w).Encode(dto.MigrateToIsolatedDBResponse{
				Status:   "schema_only",
				Message:  "Target database schema created and tenant config updated. IMPORTANT: User data (users, tokens, MFA, consents, etc.) was NOT copied automatically. Manual data migration from the Global Data Plane to the isolated DB is required before switching production traffic.",
				DataCopy: "required_manual",
			}); encErr != nil {
				logger.From(r.Context()).With(
					logger.Layer("controller"),
					logger.Op("MigrateController.MigrateToIsolatedDB"),
				).Error("encode response failed", logger.Err(encErr))
			}
		default:
			// H-BACK-1: Do NOT log raw error — it may contain DSN credentials from DB driver.
			// Log a sanitized message server-side only.
			logger.From(r.Context()).With(
				logger.Layer("controller"),
				logger.Op("MigrateController.MigrateToIsolatedDB"),
				logger.String("tenant", safeRef),
			).Error("migration failed (details omitted to avoid credential exposure)")
			httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("migration failed - check server logs for details"))
		}
		return
	}

	// Success: schema and settings updated, data copy was handled or not needed.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if encErr := json.NewEncoder(w).Encode(dto.MigrateToIsolatedDBResponse{
		Status:  "completed",
		Message: "Migration to isolated DB completed. Note: user data migration (ETL) requires a separate step if the tenant previously used the Global Data Plane.",
	}); encErr != nil {
		logger.From(r.Context()).With(
			logger.Layer("controller"),
			logger.Op("MigrateController.MigrateToIsolatedDB"),
		).Error("encode response failed", logger.Err(encErr))
	}
}
