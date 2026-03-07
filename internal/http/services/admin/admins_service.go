package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cp "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"github.com/dropDatabas3/hellojohn/internal/security/password"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
)

const adminInviteTTL = 7 * 24 * time.Hour

// ─── Interface ───

// AdminsService gestiona el CRUD de admin accounts + invite flow.
type AdminsService interface {
	// List retorna todos los admins.
	List(ctx context.Context) ([]dto.AdminResponse, error)

	// Get retorna un admin por ID.
	Get(ctx context.Context, id string) (*dto.AdminResponse, error)

	// Create crea un admin. Si req.SendInvite=true, genera un invite token
	// y devuelve el raw token en InviteLink para que el caller lo distribuya.
	Create(ctx context.Context, callerID string, req dto.CreateAdminRequest) (*dto.AdminResponse, string, error)

	// Update actualiza campos opcionales de un admin.
	Update(ctx context.Context, id string, req dto.UpdateAdminRequest) (*dto.AdminResponse, error)

	// Delete elimina un admin. No puede eliminar su propia cuenta.
	Delete(ctx context.Context, callerID, targetID string) error

	// Disable deshabilita un admin (soft disable). No puede deshabilitarse a sí mismo.
	Disable(ctx context.Context, callerID, targetID string) error

	// Enable habilita un admin previamente deshabilitado.
	Enable(ctx context.Context, id string) error

	// ValidateInvite valida un raw invite token y retorna info básica.
	ValidateInvite(ctx context.Context, rawToken string) (*dto.ValidateInviteResponse, error)

	// AcceptInvite acepta el invite: valida token, hashea password, activa admin.
	AcceptInvite(ctx context.Context, req dto.AcceptInviteRequest) (*dto.AdminResponse, error)
}

// ─── Service Errors ───

var (
	ErrAdminSelfDelete  = fmt.Errorf("admin: cannot delete your own account")
	ErrAdminSelfDisable = fmt.Errorf("admin: cannot disable your own account")
	ErrInviteExpired    = fmt.Errorf("admin invite: token expired")
	ErrInviteInvalid    = fmt.Errorf("admin invite: token invalid or already used")
	ErrWeakPassword     = fmt.Errorf("admin invite: password too short (min 8 chars)")
)

// ─── Deps ───

// AdminsDeps contiene las dependencias para AdminsService.
type AdminsDeps struct {
	ControlPlane cp.Service
	BaseURL      string // Backend base URL
	UIBaseURL    string // Frontend base URL para construir el accept-invite link
	SystemEmail  emailv2.SystemEmailService // opcional, puede ser nil
}

// ─── Implementation ───

type adminsService struct {
	deps AdminsDeps
}

// NewAdminsService crea un AdminsService.
func NewAdminsService(deps AdminsDeps) AdminsService {
	return &adminsService{deps: deps}
}

func (s *adminsService) List(ctx context.Context) ([]dto.AdminResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("admins"), logger.Op("List"))

	admins, err := s.deps.ControlPlane.ListAdmins(ctx)
	if err != nil {
		log.Error("failed to list admins", logger.Err(err))
		return nil, fmt.Errorf("list admins: %w", err)
	}

	out := make([]dto.AdminResponse, len(admins))
	for i, a := range admins {
		out[i] = toAdminResponse(&a)
	}
	return out, nil
}

func (s *adminsService) Get(ctx context.Context, id string) (*dto.AdminResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("admins"), logger.Op("Get"), logger.String("id", id))

	admin, err := s.deps.ControlPlane.GetAdmin(ctx, id)
	if err != nil {
		if errors.Is(err, cp.ErrAdminNotFound) {
			return nil, cp.ErrAdminNotFound
		}
		log.Error("failed to get admin", logger.Err(err))
		return nil, fmt.Errorf("get admin: %w", err)
	}

	r := toAdminResponse(admin)
	return &r, nil
}

func (s *adminsService) Create(ctx context.Context, callerID string, req dto.CreateAdminRequest) (*dto.AdminResponse, string, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("admins"), logger.Op("Create"), logger.String("email", req.Email))

	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" {
		return nil, "", fmt.Errorf("email required")
	}

	adminType := repository.AdminType(req.Type)
	if adminType != repository.AdminTypeGlobal && adminType != repository.AdminTypeTenant {
		return nil, "", fmt.Errorf("type must be 'global' or 'tenant'")
	}

	// Normalizar roles de TenantAccess: si un entry no tiene rol, usar req.TenantRole (default "member")
	defaultRole := req.TenantRole
	if defaultRole == "" {
		defaultRole = "member"
	}
	normAccess := make([]repository.TenantAccessEntry, len(req.TenantAccess))
	for i, entry := range req.TenantAccess {
		if entry.Role == "" {
			entry.Role = defaultRole
		}
		normAccess[i] = entry
	}

	cpInput := cp.CreateAdminInput{
		Email:        email,
		Name:         strings.TrimSpace(req.Name),
		Type:         adminType,
		TenantAccess: normAccess,
		CreatedBy:    &callerID,
		SendInvite:   req.SendInvite,
	}

	var rawToken string
	var inviteLink string

	if req.SendInvite {
		// Generate raw token + hash to pre-persist before creating admin
		raw, err := tokens.GenerateOpaqueToken(32)
		if err != nil {
			log.Error("failed to generate invite token", logger.Err(err))
			return nil, "", fmt.Errorf("generate invite token: %w", err)
		}
		hash := tokens.SHA256Base64URL(raw)
		expiresAt := time.Now().Add(adminInviteTTL)

		cpInput.PasswordHash = "" // empty for pending

		// Create admin first (pending state)
		admin, err := s.deps.ControlPlane.CreateAdmin(ctx, cpInput)
		if err != nil {
			log.Error("failed to create pending admin", logger.Err(err))
			return nil, "", fmt.Errorf("create admin: %w", err)
		}

		// Store invite token
		if err := s.deps.ControlPlane.SetAdminInvite(ctx, admin.ID, hash, expiresAt); err != nil {
			log.Error("failed to set invite token", logger.Err(err))
			// Best-effort: admin is created but without invite token — caller must retry
			return nil, "", fmt.Errorf("set invite token: %w", err)
		}

		rawToken = raw
		uiBase := strings.TrimRight(s.deps.UIBaseURL, "/")
		if uiBase == "" {
			uiBase = strings.TrimRight(s.deps.BaseURL, "/")
		}
		inviteLink = fmt.Sprintf("%s/accept-admin-invite?token=%s", uiBase, rawToken)

		// Intentar enviar email de invite via SMTP global
		if s.deps.SystemEmail != nil {
			inviterName := callerID // fallback; ideally resolve the name
			if err := s.deps.SystemEmail.SendAdminInvite(ctx, email, req.Name, inviterName, inviteLink); err != nil {
				// No es fatal: el link sigue disponible en la respuesta
				log.Warn("failed to send admin invite email", logger.Err(err))
			}
		}

		// Refresh admin to get updated state
		admin, _ = s.deps.ControlPlane.GetAdmin(ctx, admin.ID)
		r := toAdminResponse(admin)
		return &r, inviteLink, nil
	}

	// Direct creation with password
	if len(req.Password) < 8 {
		return nil, "", ErrWeakPassword
	}
	hash, err := password.Hash(password.Default, req.Password)
	if err != nil {
		log.Error("failed to hash password", logger.Err(err))
		return nil, "", fmt.Errorf("hash password: %w", err)
	}
	cpInput.PasswordHash = hash

	admin, err := s.deps.ControlPlane.CreateAdmin(ctx, cpInput)
	if err != nil {
		log.Error("failed to create admin", logger.Err(err))
		return nil, "", fmt.Errorf("create admin: %w", err)
	}

	r := toAdminResponse(admin)
	return &r, inviteLink, nil
}

func (s *adminsService) Update(ctx context.Context, id string, req dto.UpdateAdminRequest) (*dto.AdminResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("admins"), logger.Op("Update"), logger.String("id", id))

	input := cp.UpdateAdminInput{}
	if req.Email != nil {
		e := strings.TrimSpace(strings.ToLower(*req.Email))
		input.Email = &e
	}
	if req.Name != nil {
		input.Name = req.Name
	}
	if req.TenantAccess != nil {
		input.TenantAccess = &req.TenantAccess
	}

	admin, err := s.deps.ControlPlane.UpdateAdmin(ctx, id, input)
	if err != nil {
		if errors.Is(err, cp.ErrAdminNotFound) {
			return nil, cp.ErrAdminNotFound
		}
		log.Error("failed to update admin", logger.Err(err))
		return nil, fmt.Errorf("update admin: %w", err)
	}

	r := toAdminResponse(admin)
	return &r, nil
}

func (s *adminsService) Delete(ctx context.Context, callerID, targetID string) error {
	if callerID == targetID {
		return ErrAdminSelfDelete
	}
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("admins"), logger.Op("Delete"), logger.String("target_id", targetID))

	if err := s.deps.ControlPlane.DeleteAdmin(ctx, targetID); err != nil {
		if errors.Is(err, cp.ErrAdminNotFound) {
			return cp.ErrAdminNotFound
		}
		log.Error("failed to delete admin", logger.Err(err))
		return fmt.Errorf("delete admin: %w", err)
	}
	return nil
}

func (s *adminsService) Disable(ctx context.Context, callerID, targetID string) error {
	if callerID == targetID {
		return ErrAdminSelfDisable
	}
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("admins"), logger.Op("Disable"), logger.String("target_id", targetID))

	if err := s.deps.ControlPlane.DisableAdmin(ctx, targetID); err != nil {
		if errors.Is(err, cp.ErrAdminNotFound) {
			return cp.ErrAdminNotFound
		}
		log.Error("failed to disable admin", logger.Err(err))
		return fmt.Errorf("disable admin: %w", err)
	}
	return nil
}

func (s *adminsService) Enable(ctx context.Context, id string) error {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("admins"), logger.Op("Enable"), logger.String("id", id))

	if err := s.deps.ControlPlane.EnableAdmin(ctx, id); err != nil {
		if errors.Is(err, cp.ErrAdminNotFound) {
			return cp.ErrAdminNotFound
		}
		log.Error("failed to enable admin", logger.Err(err))
		return fmt.Errorf("enable admin: %w", err)
	}
	return nil
}

func (s *adminsService) ValidateInvite(ctx context.Context, rawToken string) (*dto.ValidateInviteResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("admins"), logger.Op("ValidateInvite"))

	hash := tokens.SHA256Base64URL(rawToken)
	admin, err := s.deps.ControlPlane.GetAdminByInviteToken(ctx, hash)
	if err != nil {
		if errors.Is(err, cp.ErrAdminNotFound) {
			return nil, ErrInviteInvalid
		}
		log.Error("failed to get admin by invite token", logger.Err(err))
		return nil, fmt.Errorf("validate invite: %w", err)
	}

	// Check expiry
	if admin.InviteExpiresAt != nil && admin.InviteExpiresAt.Before(time.Now()) {
		return nil, ErrInviteExpired
	}

	expiresAt := ""
	if admin.InviteExpiresAt != nil {
		expiresAt = admin.InviteExpiresAt.Format(time.RFC3339)
	}

	return &dto.ValidateInviteResponse{
		Valid:     true,
		AdminID:   admin.ID,
		Email:     admin.Email,
		Name:      admin.Name,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *adminsService) AcceptInvite(ctx context.Context, req dto.AcceptInviteRequest) (*dto.AdminResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("admins"), logger.Op("AcceptInvite"))

	if len(req.Password) < 8 {
		return nil, ErrWeakPassword
	}

	hash := tokens.SHA256Base64URL(req.Token)
	admin, err := s.deps.ControlPlane.GetAdminByInviteToken(ctx, hash)
	if err != nil {
		if errors.Is(err, cp.ErrAdminNotFound) {
			return nil, ErrInviteInvalid
		}
		log.Error("failed to get admin by invite token", logger.Err(err))
		return nil, fmt.Errorf("accept invite lookup: %w", err)
	}

	// Check expiry
	if admin.InviteExpiresAt != nil && admin.InviteExpiresAt.Before(time.Now()) {
		return nil, ErrInviteExpired
	}

	// Hash password
	pwHash, err := password.Hash(password.Default, req.Password)
	if err != nil {
		log.Error("failed to hash password", logger.Err(err))
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// Activate admin
	if err := s.deps.ControlPlane.ActivateAdminInvite(ctx, admin.ID, pwHash); err != nil {
		log.Error("failed to activate admin", logger.Err(err))
		return nil, fmt.Errorf("activate invite: %w", err)
	}

	// Fetch updated admin
	updated, err := s.deps.ControlPlane.GetAdmin(ctx, admin.ID)
	if err != nil {
		// Non-critical: admin was activated, just return partial data
		r := toAdminResponse(admin)
		r.Status = "active"
		return &r, nil
	}

	r := toAdminResponse(updated)
	return &r, nil
}

// ─── Helpers ───

// toAdminResponse convierte un repository.Admin a dto.AdminResponse.
func toAdminResponse(a *repository.Admin) dto.AdminResponse {
	status := a.Status
	if status == "" {
		if a.DisabledAt != nil {
			status = "disabled"
		} else {
			status = "active"
		}
	}

	return dto.AdminResponse{
		ID:              a.ID,
		Email:           a.Email,
		Name:            a.Name,
		Type:            string(a.Type),
		TenantAccess:    a.TenantAccess,
		Status:          status,
		LastSeenAt:      a.LastSeenAt,
		DisabledAt:      a.DisabledAt,
		InviteExpiresAt: a.InviteExpiresAt,
		CreatedAt:       a.CreatedAt,
		UpdatedAt:       a.UpdatedAt,
	}
}
