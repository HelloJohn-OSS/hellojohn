package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// TenantsController handles /v2/admin/tenants routes.
type TenantsController struct {
	service                 svc.TenantsService
	keyRotationGraceSeconds int64
}

// NewTenantsController creates a new tenants controller.
func NewTenantsController(service svc.TenantsService, keyRotationGrace int64) *TenantsController {
	if keyRotationGrace <= 0 {
		keyRotationGrace = 60
	}
	return &TenantsController{service: service, keyRotationGraceSeconds: keyRotationGrace}
}

// â”€â”€â”€ Tenants CRUD â”€â”€â”€

// ListTenants handles GET /v2/admin/tenants
func (c *TenantsController) ListTenants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ListTenants"))

	tenants, err := c.service.List(ctx)
	if err != nil {
		log.Error("list failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenants)
}

// CreateTenant handles POST /v2/admin/tenants
func (c *TenantsController) CreateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("CreateTenant"))

	var req dto.CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	created, err := c.service.Create(ctx, req)
	if err != nil {
		log.Error("create failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

// GetTenant handles GET /v2/admin/tenants/{slug}
func (c *TenantsController) GetTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("GetTenant"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	tenant, err := c.service.Get(ctx, slugOrID)
	if err != nil {
		log.Error("get failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenant)
}

// UpdateTenant handles PUT/PATCH /v2/admin/tenants/{slug}
func (c *TenantsController) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("UpdateTenant"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	var req dto.UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	updated, err := c.service.Update(ctx, slugOrID, req)
	if err != nil {
		log.Error("update failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

// DeleteTenant handles DELETE /v2/admin/tenants/{slug}
func (c *TenantsController) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("DeleteTenant"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	if err := c.service.Delete(ctx, slugOrID); err != nil {
		log.Error("delete failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// â”€â”€â”€ Settings & Keys (Stubs for now) â”€â”€â”€

func (c *TenantsController) GetSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("GetSettings"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	// Use DTO version for API stability
	settings, etag, err := c.service.GetSettingsDTO(ctx, slugOrID)
	if err != nil {
		log.Error("get settings failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	// Cache-Control: no-store
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (c *TenantsController) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("UpdateSettings"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	// Limit body size to prevent DoS (2MB)
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	defer r.Body.Close()

	// Cache-Control: no-store necessary for updates too
	w.Header().Set("Cache-Control", "no-store")

	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	if ifMatch == "" {
		httperrors.WriteError(w, httperrors.ErrPreconditionRequired)
		return
	}

	// Use DTO version for API stability
	var req dto.UpdateTenantSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	newETag, err := c.service.UpdateSettingsDTO(ctx, slugOrID, req, ifMatch)
	if err != nil {
		log.Error("update settings failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("ETag", newETag)
	w.Header().Set("Content-Type", "application/json")
	// Return {updated: true} per request
	json.NewEncoder(w).Encode(map[string]bool{"updated": true})
}

// GetPasswordPolicy handles GET /v2/admin/tenants/{id}/password-policy
func (c *TenantsController) GetPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("GetPasswordPolicy"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	settings, etag, err := c.service.GetSettingsDTO(ctx, slugOrID)
	if err != nil {
		log.Error("get password policy failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	policy := dto.SecuritySettings{}
	if settings.Security != nil {
		policy = *settings.Security
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(policy)
}

// UpdatePasswordPolicy handles PUT /v2/admin/tenants/{id}/password-policy
func (c *TenantsController) UpdatePasswordPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("UpdatePasswordPolicy"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()

	var policy dto.SecuritySettings
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	if ifMatch == "" {
		_, currentETag, err := c.service.GetSettingsDTO(ctx, slugOrID)
		if err != nil {
			log.Error("resolve current settings failed", logger.Err(err))
			httperrors.WriteError(w, mapTenantError(err))
			return
		}
		ifMatch = currentETag
	}

	updateReq := dto.UpdateTenantSettingsRequest{
		Security: &policy,
	}
	newETag, err := c.service.UpdateSettingsDTO(ctx, slugOrID, updateReq, ifMatch)
	if err != nil {
		log.Error("update password policy failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", newETag)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"updated":        true,
		"passwordPolicy": policy,
	})
}

func (c *TenantsController) RotateKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("RotateKeys"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	graceSeconds := c.keyRotationGraceSeconds
	// Query Param override
	if q := r.URL.Query().Get("graceSeconds"); q != "" {
		val, err := strconv.ParseInt(q, 10, 64)
		if err != nil || val < 0 {
			httperrors.WriteError(w, httperrors.ErrInvalidParameter.WithDetail("graceSeconds must be >= 0"))
			return
		}
		graceSeconds = val
	}

	kid, err := c.service.RotateKeys(ctx, slugOrID, graceSeconds)
	if err != nil {
		log.Error("rotate keys failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"kid": kid})
}

// â”€â”€â”€ Ops & Infra (Stubs for now) â”€â”€â”€

func (c *TenantsController) TestConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TestConnection"))

	var req struct {
		DSN string `json:"dsn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if strings.TrimSpace(req.DSN) == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("DSN is required"))
		return
	}

	if err := c.service.TestConnection(ctx, req.DSN); err != nil {
		log.Error("test connection failed", logger.Err(err))
		errMsg := err.Error()

		// Classify the error type for better user feedback
		switch {
		case strings.Contains(errMsg, "dial error") || strings.Contains(errMsg, "connection refused") ||
			strings.Contains(errMsg, "connectex") || strings.Contains(errMsg, "no such host"):
			// Connection was refused by the target server
			httperrors.WriteError(w, httperrors.ErrConnectionFailed.WithDetail("Database server rejected the connection. Verify it is running and reachable."))
		case strings.Contains(errMsg, "authentication failed") || strings.Contains(errMsg, "password"):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("Invalid credentials. Verify username and password."))
		case strings.Contains(errMsg, "database") && strings.Contains(errMsg, "does not exist"):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("The specified database does not exist."))
		case strings.Contains(errMsg, "timeout"):
			httperrors.WriteError(w, httperrors.ErrGatewayTimeout.WithDetail("Connection timed out while contacting the server."))
		default:
			httperrors.WriteError(w, httperrors.ErrBadGateway.WithDetail("Connection error: "+errMsg))
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (c *TenantsController) MigrateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("MigrateTenant"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	if err := c.service.MigrateTenant(ctx, slugOrID); err != nil {
		if strings.Contains(err.Error(), "lock") || strings.Contains(err.Error(), "busy") {
			w.Header().Set("Retry-After", "5")
			httperrors.WriteError(w, httperrors.ErrConflict.WithDetail("migration lock busy"))
			return
		}
		log.Error("migrate tenant failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "migrated"})
}

func (c *TenantsController) ApplySchema(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ApplySchema"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	var schema map[string]any
	if err := json.NewDecoder(r.Body).Decode(&schema); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if err := c.service.ApplySchema(ctx, slugOrID, schema); err != nil {
		log.Error("apply schema failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "applied"})
}

func (c *TenantsController) InfraStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("InfraStats"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	stats, err := c.service.InfraStats(ctx, slugOrID)
	if err != nil {
		log.Error("infra stats failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (c *TenantsController) TestCache(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TestCache"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	if err := c.service.TestCache(ctx, slugOrID); err != nil {
		log.Error("test cache failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (c *TenantsController) TestMailing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TestMailing"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	var req dto.SendTestEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if strings.TrimSpace(req.To) == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("recipient email required"))
		return
	}

	if err := c.service.TestMailing(ctx, slugOrID, req); err != nil {
		log.Error("test mailing failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Test email sent successfully"})
}

func (c *TenantsController) TestTenantDBConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TestTenantDBConnection"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	if err := c.service.TestTenantDBConnection(ctx, slugOrID); err != nil {
		log.Error("test tenant db failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// â”€â”€â”€ Helpers â”€â”€â”€

func mapTenantError(err error) *httperrors.AppError {
	if err == nil {
		return httperrors.ErrInternalServerError
	}
	if app, ok := err.(*httperrors.AppError); ok {
		return app
	}

	errMsg := err.Error()

	switch {
	case errors.Is(err, store.ErrTenantNotFound):
		return httperrors.ErrNotFound.WithDetail("tenant not found")
	case errors.Is(err, repository.ErrInvalidInput):
		return httperrors.ErrBadRequest.WithDetail(err.Error())
	case errors.Is(err, store.ErrPreconditionFailed):
		return httperrors.ErrPreconditionFailed
	case errors.Is(err, store.ErrNotLeader):
		return httperrors.ErrServiceUnavailable.WithDetail("not leader")
	case store.IsNoDBForTenant(err):
		return httperrors.ErrTenantNoDatabase.WithDetail("tenant has no database configured")
	case errors.Is(err, store.ErrDBUnavailable):
		return httperrors.ErrServiceUnavailable.WithDetail("global DB unavailable, try again later")

	// SMTP/Email errors
	case strings.Contains(errMsg, "Username and Password not accepted") ||
		strings.Contains(errMsg, "authentication failed") ||
		strings.Contains(errMsg, "535 "):
		return httperrors.ErrBadRequest.WithDetail("SMTP credentials were rejected. Verify username and password.")
	case strings.Contains(errMsg, "decrypt") || strings.Contains(errMsg, "formato invÃ¡lido"):
		return httperrors.ErrBadRequest.WithDetail("SMTP configuration error: password is not correctly encrypted. Save the configuration again.")
	case strings.Contains(errMsg, "smtp send") || strings.Contains(errMsg, "dial tcp"):
		return httperrors.ErrConnectionFailed.WithDetail("Could not connect to SMTP server. Verify host and port.")
	case strings.Contains(errMsg, "email"):
		return httperrors.ErrBadGateway.WithDetail("Failed to send email: " + errMsg)

	default:
		return httperrors.ErrInternalServerError.WithCause(err)
	}
}

// â”€â”€â”€ Import/Export Handlers â”€â”€â”€

// ImportFromFile handles POST /v2/admin/tenants/import
// Creates a new tenant and applies the exported config atomically (with rollback on failure).
func (c *TenantsController) ImportFromFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ImportFromFile"))

	var req dto.TenantImportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10<<20)).Decode(&req); err != nil { // 10MB limit
		httperrors.WriteError(w, httperrors.ErrInvalidJSON.WithDetail(err.Error()))
		return
	}

	result, err := c.service.CreateFromImport(ctx, req)
	if err != nil {
		log.Error("create from import failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	log.Info("tenant created from import",
		logger.String("tenant_id", result.TenantID),
		logger.String("tenant_slug", result.TenantSlug),
		logger.Int("clients", result.ItemsImported.Clients),
		logger.Int("scopes", result.ItemsImported.Scopes))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

// ValidateImport handles POST /v2/admin/tenants/{id}/import/validate
func (c *TenantsController) ValidateImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ValidateImport"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug or ID is required"))
		return
	}
	var req dto.TenantImportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10<<20)).Decode(&req); err != nil { // 10MB limit
		httperrors.WriteError(w, httperrors.ErrInvalidJSON.WithDetail(err.Error()))
		return
	}

	result, err := c.service.ValidateImport(ctx, slugOrID, req)
	if err != nil {
		log.Error("validate import failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// ImportConfig handles PUT /v2/admin/tenants/{id}/import
func (c *TenantsController) ImportConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ImportConfig"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug or ID is required"))
		return
	}
	var req dto.TenantImportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10<<20)).Decode(&req); err != nil { // 10MB limit
		httperrors.WriteError(w, httperrors.ErrInvalidJSON.WithDetail(err.Error()))
		return
	}

	result, err := c.service.ImportConfig(ctx, slugOrID, req)
	if err != nil {
		log.Error("import config failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	log.Info("import completed",
		logger.String("tenant", slugOrID),
		logger.Int("clients", result.ItemsImported.Clients),
		logger.Int("users", result.ItemsImported.Users))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// ExportConfig handles GET /v2/admin/tenants/{id}/export
func (c *TenantsController) ExportConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ExportConfig"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug or ID is required"))
		return
	}
	// Parsear query params para opciones
	opts := dto.ExportOptionsRequest{
		IncludeSettings: r.URL.Query().Get("settings") != "false",
		IncludeClients:  r.URL.Query().Get("clients") != "false",
		IncludeScopes:   r.URL.Query().Get("scopes") != "false",
		IncludeRoles:    r.URL.Query().Get("roles") == "true",   // Opt-in
		IncludeSecrets:  r.URL.Query().Get("secrets") == "true", // Opt-in: decrypt all secrets
	}

	result, err := c.service.ExportConfig(ctx, slugOrID, opts)
	if err != nil {
		log.Error("export config failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	// OpciÃ³n: descargar como archivo
	if r.URL.Query().Get("download") == "true" {
		w.Header().Set("Content-Disposition", "attachment; filename=hellojohn-export-"+slugOrID+".json")
	}

	log.Info("export completed", logger.String("tenant", slugOrID))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// PushTenant handles POST /v2/admin/tenants/{tenant_id}/push
// Exports the tenant config (with secrets) and pushes it to another HelloJohn instance.
func (c *TenantsController) PushTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("PushTenant"))

	slugOrID := r.PathValue("tenant_id")
	if slugOrID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug or ID is required"))
		return
	}

	var req dto.PushTenantRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON.WithDetail(err.Error()))
		return
	}

	if req.InstanceID == "" && (req.TargetURL == "" || req.APIKey == "") {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("provide instance_id or both target_url and api_key"))
		return
	}

	result, err := c.service.PushTenant(ctx, slugOrID, req)
	if err != nil {
		log.Error("push tenant failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	log.Info("push tenant completed",
		logger.String("tenant", slugOrID),
		logger.String("target", req.TargetURL))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
