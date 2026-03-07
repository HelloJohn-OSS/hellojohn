package admin

import (
	"encoding/json"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// MailingController handles admin mailing endpoints.
type MailingController struct {
	service svc.MailingService
}

// NewMailingController creates a new admin mailing controller.
func NewMailingController(service svc.MailingService) *MailingController {
	return &MailingController{service: service}
}

// SendTestEmail handles POST /v2/admin/mailing/test.
func (c *MailingController) SendTestEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("MailingController.SendTestEmail"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10) // 32KB

	// Parse request
	var req dto.SendTestEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid JSON"))
		return
	}

	// Get tenant from middleware
	tda := mw.MustGetTenant(ctx)

	// Get tenant SMTP settings (for fallback)
	// TODO: Get actual tenant SMTP settings from control plane
	tenantID := tda.ID()
	tenantName := tenantID // Use tenant ID as name fallback

	// Build SMTP config from tenant settings
	// For now, only support override - tenant stored SMTP requires control plane integration
	smtpCfg := svc.SMTPConfig{}

	// Call service
	result, err := c.service.SendTestEmail(ctx, tenantID, tenantName, smtpCfg, req)
	if err != nil {
		switch err {
		case svc.ErrMailingMissingTo:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("field 'to' is required"))
		case svc.ErrMailingMissingSMTP:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("no SMTP configuration available"))
		default:
			log.Error("send test email error", logger.Err(err))
			httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("SMTP send failed"))
		}
		return
	}

	// Set anti-cache headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)

	log.Debug("test email sent successfully")
}
