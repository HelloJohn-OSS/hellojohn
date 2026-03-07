package admin

import (
	"context"
	"fmt"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"github.com/dropDatabas3/hellojohn/internal/passwordpolicy"
	"github.com/dropDatabas3/hellojohn/internal/security/password"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// UserCRUDService maneja las operaciones CRUD de usuarios.
type UserCRUDService interface {
	Create(ctx context.Context, tenantID string, req dto.CreateUserRequest) (*dto.UserResponse, error)
	List(ctx context.Context, tenantID string, page, pageSize int, search string) (*dto.ListUsersResponse, error)
	Get(ctx context.Context, tenantID, userID string) (*dto.UserResponse, error)
	Update(ctx context.Context, tenantID, userID string, req dto.UpdateUserRequest) error
	Delete(ctx context.Context, tenantID, userID string) error
}

// UserCRUDDeps contiene las dependencias del service.
type UserCRUDDeps struct {
	DAL      store.DataAccessLayer
	AuditBus *audit.AuditBus
}

type userCRUDService struct {
	deps UserCRUDDeps
}

// NewUserCRUDService crea una nueva instancia del servicio.
func NewUserCRUDService(deps UserCRUDDeps) UserCRUDService {
	return &userCRUDService{deps: deps}
}

// Errores del servicio
var (
	ErrUserInvalidInput   = fmt.Errorf("invalid user input")
	ErrUserNotFound       = fmt.Errorf("user not found")
	ErrUserEmailDuplicate = fmt.Errorf("email already exists")
	ErrUserTenantNotFound = fmt.Errorf("tenant not found")
	ErrUserTenantNoDB     = fmt.Errorf("tenant has no database configured")
)

// Create crea un nuevo usuario en el tenant.
func (s *userCRUDService) Create(ctx context.Context, tenantID string, req dto.CreateUserRequest) (*dto.UserResponse, error) {
	log := logger.From(ctx)

	// 1. Validación básica
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" {
		return nil, fmt.Errorf("%w: email is required", ErrUserInvalidInput)
	}
	if req.Password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrUserInvalidInput)
	}

	// 2. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		emitAdminEventWithCanonicalTenantRef(ctx, s.deps.AuditBus, s.deps.DAL, tenantID, audit.EventUserCreated, "", "", audit.ResultFailure, map[string]any{
			"reason": "tenant_not_found",
		})
		if store.IsTenantNotFound(err) {
			return nil, ErrUserTenantNotFound
		}
		return nil, err
	}

	// 3. Verificar que tenant tenga DB (Data Plane)
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database", logger.TenantID(tenantID))
		emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserCreated, "", "", audit.ResultFailure, map[string]any{
			"reason": "tenant_db_unavailable",
		})
		return nil, ErrUserTenantNoDB
	}

	// 4. Validar política de contraseña efectiva del tenant
	violations := passwordpolicy.Validate(req.Password, tda.Settings().Security, passwordpolicy.ValidationContext{
		Email: req.Email,
		Name:  req.Name,
	})
	if len(violations) > 0 {
		emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserCreated, "", "", audit.ResultFailure, map[string]any{
			"reason": "password_policy_violation",
		})
		return nil, fmt.Errorf("%w: password policy violation: %s", ErrUserInvalidInput, violations[0].Message)
	}

	// 5. Hash de la contraseña usando Argon2id
	passwordHash, err := password.Hash(password.Default, req.Password)
	if err != nil {
		log.Error("failed to hash password", logger.Err(err))
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// 6. Crear usuario
	user, _, err := tda.Users().Create(ctx, repository.CreateUserInput{
		TenantID:       tda.ID(),
		Email:          req.Email,
		PasswordHash:   passwordHash,
		Name:           req.Name,
		GivenName:      req.GivenName,
		FamilyName:     req.FamilyName,
		Picture:        req.Picture,
		Locale:         req.Locale,
		CustomFields:   req.CustomFields,
		SourceClientID: req.SourceClientID,
	})
	if err != nil {
		if repository.IsConflict(err) {
			emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserCreated, "", "", audit.ResultFailure, map[string]any{
				"reason": "email_conflict",
			})
			return nil, ErrUserEmailDuplicate
		}
		emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserCreated, "", "", audit.ResultError, map[string]any{
			"reason": "create_failed",
		})
		log.Error("failed to create user", logger.Err(err))
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	meta := map[string]any{}
	if strings.TrimSpace(req.SourceClientID) != "" {
		meta["client_id"] = req.SourceClientID
	}
	emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserCreated, user.ID, audit.TargetUser, audit.ResultSuccess, meta)

	log.Info("user created", logger.UserID(user.ID))

	return mapUserToResponse(user), nil
}

// List lista los usuarios del tenant con paginación.
func (s *userCRUDService) List(ctx context.Context, tenantID string, page, pageSize int, search string) (*dto.ListUsersResponse, error) {
	log := logger.From(ctx)

	// 1. Validación de paginación
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}

	// 2. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		if store.IsTenantNotFound(err) {
			return nil, ErrUserTenantNotFound
		}
		return nil, err
	}

	// 3. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database", logger.TenantID(tenantID))
		return nil, ErrUserTenantNoDB
	}

	// 4. Listar usuarios
	offset := (page - 1) * pageSize
	users, err := tda.Users().List(ctx, tda.ID(), repository.ListUsersFilter{
		Limit:  pageSize,
		Offset: offset,
		Search: strings.TrimSpace(search),
	})
	if err != nil {
		log.Error("failed to list users", logger.Err(err))
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// 5. Mapear a DTOs
	userResponses := make([]dto.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = *mapUserToResponse(&user)
	}

	log.Info("users listed", logger.Count(len(users)), logger.Int("page", page), logger.Int("page_size", pageSize))

	return &dto.ListUsersResponse{
		Users:      userResponses,
		TotalCount: len(users), // TODO: En el futuro, obtener count total de la DB
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

// Get obtiene un usuario específico del tenant.
func (s *userCRUDService) Get(ctx context.Context, tenantID, userID string) (*dto.UserResponse, error) {
	log := logger.From(ctx)

	// 1. Validación
	if userID == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrUserInvalidInput)
	}

	// 2. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		if store.IsTenantNotFound(err) {
			return nil, ErrUserTenantNotFound
		}
		return nil, err
	}

	// 3. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database", logger.TenantID(tenantID))
		return nil, ErrUserTenantNoDB
	}

	// 4. Obtener usuario
	user, err := tda.Users().GetByID(ctx, userID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		log.Error("failed to get user", logger.Err(err), logger.UserID(userID))
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	log.Info("user retrieved", logger.UserID(user.ID))

	return mapUserToResponse(user), nil
}

// Update actualiza los datos de un usuario.
func (s *userCRUDService) Update(ctx context.Context, tenantID, userID string, req dto.UpdateUserRequest) error {
	log := logger.From(ctx)

	// 1. Validación
	if userID == "" {
		return fmt.Errorf("%w: user_id is required", ErrUserInvalidInput)
	}

	// 2. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		emitAdminEventWithCanonicalTenantRef(ctx, s.deps.AuditBus, s.deps.DAL, tenantID, audit.EventUserUpdated, userID, audit.TargetUser, audit.ResultFailure, map[string]any{
			"reason": "tenant_not_found",
		})
		if store.IsTenantNotFound(err) {
			return ErrUserTenantNotFound
		}
		return err
	}

	// 3. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database", logger.TenantID(tenantID))
		emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserUpdated, userID, audit.TargetUser, audit.ResultFailure, map[string]any{
			"reason": "tenant_db_unavailable",
		})
		return ErrUserTenantNoDB
	}

	// 4. Actualizar usuario
	var customFields map[string]any
	if req.CustomFields != nil {
		customFields = *req.CustomFields
	}

	err = tda.Users().Update(ctx, userID, repository.UpdateUserInput{
		Name:           req.Name,
		GivenName:      req.GivenName,
		FamilyName:     req.FamilyName,
		Picture:        req.Picture,
		Locale:         req.Locale,
		SourceClientID: req.SourceClientID,
		CustomFields:   customFields,
	})
	if err != nil {
		if repository.IsNotFound(err) {
			emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserUpdated, userID, audit.TargetUser, audit.ResultFailure, map[string]any{
				"reason": "user_not_found",
			})
			return ErrUserNotFound
		}
		emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserUpdated, userID, audit.TargetUser, audit.ResultError, map[string]any{
			"reason": "update_failed",
		})
		log.Error("failed to update user", logger.Err(err), logger.UserID(userID))
		return fmt.Errorf("failed to update user: %w", err)
	}

	emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserUpdated, userID, audit.TargetUser, audit.ResultSuccess, nil)

	log.Info("user updated", logger.UserID(userID))

	return nil
}

// Delete elimina un usuario del tenant.
func (s *userCRUDService) Delete(ctx context.Context, tenantID, userID string) error {
	log := logger.From(ctx)

	// 1. Validación
	if userID == "" {
		return fmt.Errorf("%w: user_id is required", ErrUserInvalidInput)
	}

	// 2. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		emitAdminEventWithCanonicalTenantRef(ctx, s.deps.AuditBus, s.deps.DAL, tenantID, audit.EventUserDeleted, userID, audit.TargetUser, audit.ResultFailure, map[string]any{
			"reason": "tenant_not_found",
		})
		if store.IsTenantNotFound(err) {
			return ErrUserTenantNotFound
		}
		return err
	}

	// 3. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database", logger.TenantID(tenantID))
		emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserDeleted, userID, audit.TargetUser, audit.ResultFailure, map[string]any{
			"reason": "tenant_db_unavailable",
		})
		return ErrUserTenantNoDB
	}

	// 4. Eliminar usuario
	err = tda.Users().Delete(ctx, userID)
	if err != nil {
		if repository.IsNotFound(err) {
			emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserDeleted, userID, audit.TargetUser, audit.ResultFailure, map[string]any{
				"reason": "user_not_found",
			})
			return ErrUserNotFound
		}
		emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserDeleted, userID, audit.TargetUser, audit.ResultError, map[string]any{
			"reason": "delete_failed",
		})
		log.Error("failed to delete user", logger.Err(err), logger.UserID(userID))
		return fmt.Errorf("failed to delete user: %w", err)
	}

	emitAdminEvent(ctx, s.deps.AuditBus, tda.ID(), audit.EventUserDeleted, userID, audit.TargetUser, audit.ResultSuccess, nil)

	log.Info("user deleted", logger.UserID(userID))

	return nil
}

// mapUserToResponse convierte un repository.User a dto.UserResponse.
func mapUserToResponse(user *repository.User) *dto.UserResponse {
	return &dto.UserResponse{
		ID:             user.ID,
		TenantID:       user.TenantID,
		Email:          user.Email,
		Name:           user.Name,
		GivenName:      user.GivenName,
		FamilyName:     user.FamilyName,
		Picture:        user.Picture,
		Locale:         user.Locale,
		EmailVerified:  user.EmailVerified,
		SourceClientID: user.SourceClientID,
		CreatedAt:      user.CreatedAt,
		DisabledAt:     user.DisabledAt,
		DisabledUntil:  user.DisabledUntil,
		DisabledReason: user.DisabledReason,
		DisabledBy:     nil, // TODO: Agregar DisabledBy al repository.User si no existe
		CustomFields:   user.CustomFields,
	}
}
