package controlplane

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// ─── Admin Operations ───

// ListAdmins retorna todos los administradores del sistema.
func (s *service) ListAdmins(ctx context.Context) ([]repository.Admin, error) {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("List"),
	)

	config := s.store.ConfigAccess()
	admins, err := config.Admins().List(ctx, repository.AdminFilter{})
	if err != nil {
		log.Error("failed to list admins", logger.Err(err))
		return nil, fmt.Errorf("list admins: %w", err)
	}

	log.Debug("admins listed", logger.Int("count", len(admins)))
	return admins, nil
}

// GetAdmin busca un admin por su ID.
func (s *service) GetAdmin(ctx context.Context, id string) (*repository.Admin, error) {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("GetAdmin"),
		logger.String("admin_id", id),
	)

	config := s.store.ConfigAccess()
	admin, err := config.Admins().GetByID(ctx, id)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("admin not found")
			return nil, ErrAdminNotFound
		}
		log.Error("failed to get admin", logger.Err(err))
		return nil, fmt.Errorf("get admin: %w", err)
	}

	log.Debug("admin found")
	return admin, nil
}

// GetAdminByEmail busca un admin por su email.
func (s *service) GetAdminByEmail(ctx context.Context, email string) (*repository.Admin, error) {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("GetAdminByEmail"),
		logger.String("email", email),
	)

	// Normalizar email
	email = strings.TrimSpace(strings.ToLower(email))

	config := s.store.ConfigAccess()
	admin, err := config.Admins().GetByEmail(ctx, email)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("admin not found")
			return nil, ErrAdminNotFound
		}
		log.Error("failed to get admin by email", logger.Err(err))
		return nil, fmt.Errorf("get admin by email: %w", err)
	}

	log.Debug("admin found by email")
	return admin, nil
}

// CreateAdmin crea un nuevo administrador.
func (s *service) CreateAdmin(ctx context.Context, input CreateAdminInput) (*repository.Admin, error) {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("CreateAdmin"),
		logger.String("email", input.Email),
		logger.String("type", string(input.Type)),
	)

	// Validaciones
	if input.Email == "" {
		return nil, fmt.Errorf("%w: email required", ErrBadInput)
	}
	if !input.SendInvite && input.PasswordHash == "" {
		return nil, fmt.Errorf("%w: password_hash required when not using invite", ErrBadInput)
	}
	if input.Type != repository.AdminTypeGlobal && input.Type != repository.AdminTypeTenant {
		return nil, fmt.Errorf("%w: invalid admin type", ErrBadInput)
	}

	// Normalizar email
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	// Validar email único
	config := s.store.ConfigAccess()
	existing, err := config.Admins().GetByEmail(ctx, input.Email)
	if err == nil && existing != nil {
		log.Warn("email already exists")
		return nil, fmt.Errorf("%w: email already exists", ErrBadInput)
	}

	// Crear admin
	status := "active"
	if input.SendInvite {
		status = "pending"
	}
	repoInput := repository.CreateAdminInput{
		Email:        input.Email,
		PasswordHash: input.PasswordHash,
		Name:         input.Name,
		Type:         input.Type,
		TenantAccess: input.TenantAccess,
		CreatedBy:    input.CreatedBy,
		Status:       status,
	}

	admin, err := config.Admins().Create(ctx, repoInput)
	if err != nil {
		if repository.IsConflict(err) {
			log.Warn("email conflict")
			return nil, fmt.Errorf("%w: email already exists", ErrBadInput)
		}
		log.Error("failed to create admin", logger.Err(err))
		return nil, fmt.Errorf("create admin: %w", err)
	}

	log.Info("admin created", logger.String("admin_id", admin.ID))
	return admin, nil
}

// UpdateAdmin actualiza un administrador existente.
func (s *service) UpdateAdmin(ctx context.Context, id string, input UpdateAdminInput) (*repository.Admin, error) {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("UpdateAdmin"),
		logger.String("admin_id", id),
	)

	// Validar que el admin existe
	config := s.store.ConfigAccess()
	_, err := config.Admins().GetByID(ctx, id)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("admin not found")
			return nil, ErrAdminNotFound
		}
		log.Error("failed to get admin", logger.Err(err))
		return nil, fmt.Errorf("get admin: %w", err)
	}

	// Normalizar email si se proporciona
	if input.Email != nil {
		normalized := strings.TrimSpace(strings.ToLower(*input.Email))
		input.Email = &normalized
	}

	// Actualizar
	repoInput := repository.UpdateAdminInput{
		Email:        input.Email,
		Name:         input.Name,
		TenantAccess: input.TenantAccess,
		DisabledAt:   input.DisabledAt,
	}

	admin, err := config.Admins().Update(ctx, id, repoInput)
	if err != nil {
		if repository.IsConflict(err) {
			log.Warn("email conflict")
			return nil, fmt.Errorf("%w: email already exists", ErrBadInput)
		}
		log.Error("failed to update admin", logger.Err(err))
		return nil, fmt.Errorf("update admin: %w", err)
	}

	log.Info("admin updated")
	return admin, nil
}

// DeleteAdmin elimina un administrador.
func (s *service) DeleteAdmin(ctx context.Context, id string) error {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("DeleteAdmin"),
		logger.String("admin_id", id),
	)

	config := s.store.ConfigAccess()
	err := config.Admins().Delete(ctx, id)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("admin not found")
			return ErrAdminNotFound
		}
		log.Error("failed to delete admin", logger.Err(err))
		return fmt.Errorf("delete admin: %w", err)
	}

	log.Info("admin deleted")
	return nil
}

// UpdateAdminPassword actualiza el password hash de un administrador.
func (s *service) UpdateAdminPassword(ctx context.Context, id string, passwordHash string) error {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("UpdateAdminPassword"),
		logger.String("admin_id", id),
	)

	if passwordHash == "" {
		return fmt.Errorf("%w: password_hash required", ErrBadInput)
	}

	config := s.store.ConfigAccess()
	input := repository.UpdateAdminInput{
		PasswordHash: &passwordHash,
	}

	_, err := config.Admins().Update(ctx, id, input)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("admin not found")
			return ErrAdminNotFound
		}
		log.Error("failed to update admin password", logger.Err(err))
		return fmt.Errorf("update admin password: %w", err)
	}

	log.Info("admin password updated")
	return nil
}

// CheckAdminPassword verifica que un password coincida con el hash usando Argon2id.
func (s *service) CheckAdminPassword(passwordHash, plainPassword string) bool {
	config := s.store.ConfigAccess()
	return config.Admins().CheckPassword(passwordHash, plainPassword)
}

// ─── Admin Refresh Tokens ───

// CreateAdminRefreshToken persiste un refresh token de admin.
func (s *service) CreateAdminRefreshToken(ctx context.Context, input AdminRefreshTokenInput) error {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("CreateAdminRefreshToken"),
		logger.String("admin_id", input.AdminID),
	)

	if input.AdminID == "" || input.TokenHash == "" {
		return fmt.Errorf("%w: admin_id and token_hash required", ErrBadInput)
	}

	config := s.store.ConfigAccess()
	err := config.AdminRefreshTokens().Create(ctx, repository.CreateAdminRefreshTokenInput{
		AdminID:   input.AdminID,
		TokenHash: input.TokenHash,
		ExpiresAt: input.ExpiresAt,
	})
	if err != nil {
		log.Error("failed to create admin refresh token", logger.Err(err))
		return fmt.Errorf("create admin refresh token: %w", err)
	}

	log.Debug("admin refresh token created")
	return nil
}

// GetAdminRefreshToken busca un refresh token por su hash.
func (s *service) GetAdminRefreshToken(ctx context.Context, tokenHash string) (*AdminRefreshToken, error) {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("GetAdminRefreshToken"),
	)

	config := s.store.ConfigAccess()
	token, err := config.AdminRefreshTokens().GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("refresh token not found")
			return nil, ErrRefreshTokenNotFound
		}
		log.Error("failed to get admin refresh token", logger.Err(err))
		return nil, fmt.Errorf("get admin refresh token: %w", err)
	}

	log.Debug("admin refresh token found")
	return &AdminRefreshToken{
		TokenHash: token.TokenHash,
		AdminID:   token.AdminID,
		ExpiresAt: token.ExpiresAt,
		CreatedAt: token.CreatedAt,
	}, nil
}

// DeleteAdminRefreshToken elimina un refresh token.
func (s *service) DeleteAdminRefreshToken(ctx context.Context, tokenHash string) error {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("DeleteAdminRefreshToken"),
	)

	config := s.store.ConfigAccess()
	err := config.AdminRefreshTokens().Delete(ctx, tokenHash)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("refresh token not found")
			return ErrRefreshTokenNotFound
		}
		log.Error("failed to delete admin refresh token", logger.Err(err))
		return fmt.Errorf("delete admin refresh token: %w", err)
	}

	log.Debug("admin refresh token deleted")
	return nil
}

// CleanupExpiredAdminRefreshTokens elimina todos los refresh tokens expirados.
func (s *service) CleanupExpiredAdminRefreshTokens(ctx context.Context) (int, error) {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("CleanupExpiredAdminRefreshTokens"),
	)

	config := s.store.ConfigAccess()
	count, err := config.AdminRefreshTokens().DeleteExpired(ctx, time.Now())
	if err != nil {
		log.Error("failed to cleanup expired admin refresh tokens", logger.Err(err))
		return 0, fmt.Errorf("cleanup expired admin refresh tokens: %w", err)
	}

	log.Info("expired admin refresh tokens cleaned up", logger.Int("count", count))
	return count, nil
}

// ─── Invite Methods ───

// SetAdminInvite almacena un invite token hash y marca al admin como pending.
func (s *service) SetAdminInvite(ctx context.Context, id, tokenHash string, expiresAt time.Time) error {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("SetAdminInvite"),
		logger.String("admin_id", id),
	)

	config := s.store.ConfigAccess()
	err := config.Admins().SetInviteToken(ctx, id, tokenHash, expiresAt)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("admin not found")
			return ErrAdminNotFound
		}
		log.Error("failed to set invite token", logger.Err(err))
		return fmt.Errorf("set admin invite: %w", err)
	}

	log.Info("admin invite token set")
	return nil
}

// GetAdminByInviteToken busca un admin por el raw token (hash calculado internamente).
func (s *service) GetAdminByInviteToken(ctx context.Context, tokenHash string) (*repository.Admin, error) {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("GetAdminByInviteToken"),
	)

	config := s.store.ConfigAccess()
	admin, err := config.Admins().GetByInviteTokenHash(ctx, tokenHash)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("invite token not found or expired")
			return nil, ErrAdminNotFound
		}
		log.Error("failed to get admin by invite token", logger.Err(err))
		return nil, fmt.Errorf("get admin by invite token: %w", err)
	}

	log.Debug("admin found by invite token")
	return admin, nil
}

// ActivateAdminInvite activa un admin pendiente con el password proporcionado.
func (s *service) ActivateAdminInvite(ctx context.Context, id, passwordHash string) error {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("ActivateAdminInvite"),
		logger.String("admin_id", id),
	)

	if passwordHash == "" {
		return fmt.Errorf("%w: password_hash required", ErrBadInput)
	}

	config := s.store.ConfigAccess()
	err := config.Admins().ActivateWithPassword(ctx, id, passwordHash)
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("admin not found")
			return ErrAdminNotFound
		}
		log.Error("failed to activate admin", logger.Err(err))
		return fmt.Errorf("activate admin invite: %w", err)
	}

	log.Info("admin invite activated")
	return nil
}

// DisableAdmin deshabilita un admin existente.
func (s *service) DisableAdmin(ctx context.Context, id string) error {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("DisableAdmin"),
		logger.String("admin_id", id),
	)

	now := time.Now()
	config := s.store.ConfigAccess()
	_, err := config.Admins().Update(ctx, id, repository.UpdateAdminInput{
		DisabledAt: &now,
	})
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("admin not found")
			return ErrAdminNotFound
		}
		log.Error("failed to disable admin", logger.Err(err))
		return fmt.Errorf("disable admin: %w", err)
	}

	log.Info("admin disabled")
	return nil
}

// EnableAdmin habilita un admin previamente deshabilitado.
func (s *service) EnableAdmin(ctx context.Context, id string) error {
	log := logger.From(ctx).With(
		logger.Layer("controlplane"),
		logger.Component("admins"),
		logger.Op("EnableAdmin"),
		logger.String("admin_id", id),
	)

	config := s.store.ConfigAccess()
	_, err := config.Admins().Update(ctx, id, repository.UpdateAdminInput{
		ClearDisabledAt: true,
	})
	if err != nil {
		if repository.IsNotFound(err) {
			log.Warn("admin not found")
			return ErrAdminNotFound
		}
		log.Error("failed to enable admin", logger.Err(err))
		return fmt.Errorf("enable admin: %w", err)
	}

	log.Info("admin enabled")
	return nil
}

func strPtr(s string) *string { return &s }

// ─── Errors ───

var (
	ErrAdminNotFound        = fmt.Errorf("control plane: admin not found")
	ErrRefreshTokenNotFound = fmt.Errorf("control plane: refresh token not found")
)
