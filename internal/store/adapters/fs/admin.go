package fs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/security/password"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// adminRepo implementa repository.AdminRepository usando FileSystem.
// Los admins se almacenan en: <fsRoot>/admins/admins.yaml
type adminRepo struct {
	fsRoot string
	mu     sync.RWMutex
}

// newAdminRepo crea un nuevo repositorio de admins basado en FS.
func newAdminRepo(fsRoot string) repository.AdminRepository {
	return &adminRepo{
		fsRoot: fsRoot,
	}
}

// adminsFile estructura del archivo admins.yaml
type adminsFile struct {
	Admins []repository.Admin `yaml:"admins"`
}

// getAdminsPath retorna la ruta al archivo admins.yaml
func (r *adminRepo) getAdminsPath() string {
	return filepath.Join(r.fsRoot, "admins", "admins.yaml")
}

// ensureAdminsDir crea el directorio de admins si no existe
func (r *adminRepo) ensureAdminsDir() error {
	adminsDir := filepath.Join(r.fsRoot, "admins")
	return os.MkdirAll(adminsDir, 0755)
}

// readAdmins lee todos los admins del archivo
func (r *adminRepo) readAdmins() ([]repository.Admin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	path := r.getAdminsPath()

	// Si el archivo no existe, retornar lista vacía
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []repository.Admin{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read admins file: %w", err)
	}

	var file adminsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse admins file: %w", err)
	}

	// Migración legacy: convertir assigned_tenants → tenant_access con rol "owner"
	for i, admin := range file.Admins {
		if len(admin.AssignedTenants) > 0 && len(admin.TenantAccess) == 0 {
			entries := make([]repository.TenantAccessEntry, len(admin.AssignedTenants))
			for j, slug := range admin.AssignedTenants {
				entries[j] = repository.TenantAccessEntry{TenantID: slug, Role: "owner"}
			}
			file.Admins[i].TenantAccess = entries
		}
	}

	return file.Admins, nil
}

// writeAdmins escribe todos los admins al archivo
func (r *adminRepo) writeAdmins(admins []repository.Admin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Asegurar que el directorio existe
	if err := r.ensureAdminsDir(); err != nil {
		return fmt.Errorf("failed to ensure admins directory: %w", err)
	}

	file := adminsFile{
		Admins: admins,
	}

	data, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("failed to marshal admins: %w", err)
	}

	path := r.getAdminsPath()

	// Escribir atómicamente (write to temp + rename)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath) // Cleanup
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// List implementa AdminRepository.List
func (r *adminRepo) List(ctx context.Context, filter repository.AdminFilter) ([]repository.Admin, error) {
	admins, err := r.readAdmins()
	if err != nil {
		return nil, err
	}

	// Aplicar filtros
	var filtered []repository.Admin
	for _, admin := range admins {
		// Filtro por tipo
		if filter.Type != nil && admin.Type != *filter.Type {
			continue
		}

		// Filtro por disabled
		if filter.Disabled != nil {
			isDisabled := admin.DisabledAt != nil
			if *filter.Disabled != isDisabled {
				continue
			}
		}

		filtered = append(filtered, admin)
	}

	// Aplicar paginación
	if filter.Offset > 0 {
		if filter.Offset >= len(filtered) {
			return []repository.Admin{}, nil
		}
		filtered = filtered[filter.Offset:]
	}

	if filter.Limit > 0 && filter.Limit < len(filtered) {
		filtered = filtered[:filter.Limit]
	}

	return filtered, nil
}

// GetByID implementa AdminRepository.GetByID
func (r *adminRepo) GetByID(ctx context.Context, id string) (*repository.Admin, error) {
	admins, err := r.readAdmins()
	if err != nil {
		return nil, err
	}

	for _, admin := range admins {
		if admin.ID == id {
			return &admin, nil
		}
	}

	return nil, repository.ErrNotFound
}

// GetByEmail implementa AdminRepository.GetByEmail
func (r *adminRepo) GetByEmail(ctx context.Context, email string) (*repository.Admin, error) {
	admins, err := r.readAdmins()
	if err != nil {
		return nil, err
	}

	for _, admin := range admins {
		if admin.Email == email {
			return &admin, nil
		}
	}

	return nil, repository.ErrNotFound
}

// Create implementa AdminRepository.Create
func (r *adminRepo) Create(ctx context.Context, input repository.CreateAdminInput) (*repository.Admin, error) {
	// Validar input
	if input.Email == "" {
		return nil, repository.ErrInvalidInput
	}
	if input.PasswordHash == "" {
		return nil, repository.ErrInvalidInput
	}
	if input.Type != repository.AdminTypeGlobal && input.Type != repository.AdminTypeTenant {
		return nil, repository.ErrInvalidInput
	}

	admins, err := r.readAdmins()
	if err != nil {
		return nil, err
	}

	// Verificar que el email no exista
	for _, admin := range admins {
		if admin.Email == input.Email {
			return nil, repository.ErrConflict
		}
	}

	// Crear admin
	now := time.Now()
	admin := repository.Admin{
		ID:           uuid.New().String(),
		Email:        input.Email,
		PasswordHash: input.PasswordHash,
		Name:         input.Name,
		Type:         input.Type,
		TenantAccess: input.TenantAccess,
		CreatedAt:    now,
		UpdatedAt:    now,
		CreatedBy:    input.CreatedBy,
		// Invite fields
		Status:          input.Status,
		InviteTokenHash: input.InviteTokenHash,
		InviteExpiresAt: input.InviteExpiresAt,
	}

	// Agregar a la lista
	admins = append(admins, admin)

	// Escribir al archivo
	if err := r.writeAdmins(admins); err != nil {
		return nil, err
	}

	return &admin, nil
}

// Update implementa AdminRepository.Update
func (r *adminRepo) Update(ctx context.Context, id string, input repository.UpdateAdminInput) (*repository.Admin, error) {
	admins, err := r.readAdmins()
	if err != nil {
		return nil, err
	}

	// Buscar el admin
	found := false
	var updated repository.Admin

	for i, admin := range admins {
		if admin.ID == id {
			found = true

			// Aplicar updates
			if input.Email != nil {
				admin.Email = *input.Email
			}
			if input.PasswordHash != nil {
				admin.PasswordHash = *input.PasswordHash
			}
			if input.Name != nil {
				admin.Name = *input.Name
			}
			if input.TenantAccess != nil {
				admin.TenantAccess = *input.TenantAccess
			}
			if input.DisabledAt != nil {
				admin.DisabledAt = input.DisabledAt
			}
			if input.ClearDisabledAt {
				admin.DisabledAt = nil
			}
			if input.Status != nil {
				admin.Status = *input.Status
			}
			if input.InviteTokenHash != nil {
				admin.InviteTokenHash = *input.InviteTokenHash
			}
			if input.InviteExpiresAt != nil {
				admin.InviteExpiresAt = *input.InviteExpiresAt
			}

			admin.UpdatedAt = time.Now()
			admins[i] = admin
			updated = admin
			break
		}
	}

	if !found {
		return nil, repository.ErrNotFound
	}

	// Escribir al archivo
	if err := r.writeAdmins(admins); err != nil {
		return nil, err
	}

	return &updated, nil
}

// Delete implementa AdminRepository.Delete
func (r *adminRepo) Delete(ctx context.Context, id string) error {
	admins, err := r.readAdmins()
	if err != nil {
		return err
	}

	// Buscar y eliminar
	found := false
	var filtered []repository.Admin

	for _, admin := range admins {
		if admin.ID == id {
			found = true
			continue
		}
		filtered = append(filtered, admin)
	}

	if !found {
		return repository.ErrNotFound
	}

	// Escribir al archivo
	return r.writeAdmins(filtered)
}

// CheckPassword implementa AdminRepository.CheckPassword
func (r *adminRepo) CheckPassword(passwordHash, plainPassword string) bool {
	// Verifica el hash usando argon2id
	return password.Verify(plainPassword, passwordHash)
}

// UpdateLastSeen implementa AdminRepository.UpdateLastSeen
func (r *adminRepo) UpdateLastSeen(ctx context.Context, id string) error {
	now := time.Now()
	_, err := r.Update(ctx, id, repository.UpdateAdminInput{
		// Solo actualizamos UpdatedAt implícitamente
	})
	if err != nil {
		return err
	}

	// Actualizar LastSeenAt manualmente (no está en UpdateAdminInput)
	admins, err := r.readAdmins()
	if err != nil {
		return err
	}

	for i, admin := range admins {
		if admin.ID == id {
			admins[i].LastSeenAt = &now
			return r.writeAdmins(admins)
		}
	}

	return repository.ErrNotFound
}

// AssignTenants implementa AdminRepository.AssignTenants
func (r *adminRepo) AssignTenants(ctx context.Context, adminID string, tenantIDs []string) error {
	entries := make([]repository.TenantAccessEntry, len(tenantIDs))
	for i, slug := range tenantIDs {
		entries[i] = repository.TenantAccessEntry{TenantID: slug, Role: "owner"}
	}
	_, err := r.Update(ctx, adminID, repository.UpdateAdminInput{
		TenantAccess: &entries,
	})
	return err
}

// HasAccessToTenant implementa AdminRepository.HasAccessToTenant
func (r *adminRepo) HasAccessToTenant(ctx context.Context, adminID, tenantID string) (bool, error) {
	admin, err := r.GetByID(ctx, adminID)
	if err != nil {
		return false, err
	}

	// Admins globales tienen acceso a todo
	if admin.Type == repository.AdminTypeGlobal {
		return true, nil
	}

	// Admins de tenant solo tienen acceso a sus tenants asignados
	for _, entry := range admin.TenantAccess {
		if entry.TenantID == tenantID {
			return true, nil
		}
	}

	return false, nil
}

// SetInviteToken implementa AdminRepository.SetInviteToken
func (r *adminRepo) SetInviteToken(ctx context.Context, id, tokenHash string, expiresAt time.Time) error {
	admins, err := r.readAdmins()
	if err != nil {
		return err
	}

	found := false
	for i, a := range admins {
		if a.ID == id {
			found = true
			admins[i].InviteTokenHash = tokenHash
			admins[i].InviteExpiresAt = &expiresAt
			admins[i].Status = "pending"
			admins[i].UpdatedAt = time.Now()
			break
		}
	}

	if !found {
		return repository.ErrNotFound
	}

	return r.writeAdmins(admins)
}

// GetByInviteTokenHash implementa AdminRepository.GetByInviteTokenHash
func (r *adminRepo) GetByInviteTokenHash(ctx context.Context, tokenHash string) (*repository.Admin, error) {
	admins, err := r.readAdmins()
	if err != nil {
		return nil, err
	}

	for _, a := range admins {
		if a.InviteTokenHash == tokenHash && a.Status == "pending" {
			copy := a
			return &copy, nil
		}
	}

	return nil, repository.ErrNotFound
}

// ActivateWithPassword implementa AdminRepository.ActivateWithPassword
func (r *adminRepo) ActivateWithPassword(ctx context.Context, id, passwordHash string) error {
	admins, err := r.readAdmins()
	if err != nil {
		return err
	}

	found := false
	for i, a := range admins {
		if a.ID == id {
			found = true
			admins[i].PasswordHash = passwordHash
			admins[i].InviteTokenHash = ""
			admins[i].InviteExpiresAt = nil
			admins[i].Status = "active"
			admins[i].UpdatedAt = time.Now()
			break
		}
	}

	if !found {
		return repository.ErrNotFound
	}

	return r.writeAdmins(admins)
}

// Cloud email verification methods — stubs for the FS adapter.
// The FS adapter is used for OSS/dev; cloud email verification requires a DB (Global DB).

func (r *adminRepo) CreateEmailVerification(_ context.Context, _ repository.AdminEmailVerification) error {
	return fmt.Errorf("adminRepo (fs): CreateEmailVerification not supported in filesystem mode")
}

func (r *adminRepo) GetEmailVerificationByHash(_ context.Context, _ string) (*repository.AdminEmailVerification, error) {
	return nil, fmt.Errorf("adminRepo (fs): GetEmailVerificationByHash not supported in filesystem mode")
}

func (r *adminRepo) MarkEmailVerificationUsed(_ context.Context, _ string) error {
	return fmt.Errorf("adminRepo (fs): MarkEmailVerificationUsed not supported in filesystem mode")
}

func (r *adminRepo) UpdateEmailVerified(ctx context.Context, adminID string, verified bool) error {
	admins, err := r.readAdmins()
	if err != nil {
		return err
	}
	for i, a := range admins {
		if a.ID == adminID {
			admins[i].EmailVerified = verified
			if verified {
				admins[i].Status = "active"
			}
			admins[i].UpdatedAt = time.Now()
			return r.writeAdmins(admins)
		}
	}
	return repository.ErrNotFound
}

func (r *adminRepo) UpdateSocialProvider(ctx context.Context, adminID, provider, plan string) error {
	admins, err := r.readAdmins()
	if err != nil {
		return err
	}
	for i, a := range admins {
		if a.ID == adminID {
			admins[i].SocialProvider = provider
			admins[i].Plan = plan
			admins[i].UpdatedAt = time.Now()
			return r.writeAdmins(admins)
		}
	}
	return repository.ErrNotFound
}

// UpdatePlan actualiza el campo Plan del admin.
func (r *adminRepo) UpdatePlan(ctx context.Context, adminID, plan string) error {
	admins, err := r.readAdmins()
	if err != nil {
		return err
	}
	for i, a := range admins {
		if a.ID == adminID {
			admins[i].Plan = plan
			admins[i].UpdatedAt = time.Now()
			return r.writeAdmins(admins)
		}
	}
	return repository.ErrNotFound
}

// CountTenantsByAdmin cuenta los tenants a los que tiene acceso el admin.
func (r *adminRepo) CountTenantsByAdmin(_ context.Context, adminID string) (int, error) {
	admins, err := r.readAdmins()
	if err != nil {
		return 0, err
	}
	for _, a := range admins {
		if a.ID == adminID {
			if a.Type == repository.AdminTypeGlobal {
				// Global admins: count all tenants in the FS
				tenantDir := filepath.Join(r.fsRoot, "tenants")
				entries, err2 := os.ReadDir(tenantDir)
				if err2 != nil {
					return 0, nil // no tenants dir = 0
				}
				count := 0
				for _, e := range entries {
					if e.IsDir() {
						count++
					}
				}
				return count, nil
			}
			return len(a.TenantAccess), nil
		}
	}
	return 0, repository.ErrNotFound
}

// CountAdminsByOwner cuenta los admins que fueron creados por el admin dado.
func (r *adminRepo) CountAdminsByOwner(_ context.Context, adminID string) (int, error) {
	admins, err := r.readAdmins()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, a := range admins {
		if a.CreatedBy != nil && *a.CreatedBy == adminID {
			count++
		}
	}
	return count, nil
}

// GetCurrentMAU retorna el MAU actual para el admin. Stub: retorna 0 (fail-open).
// El MAU tracking completo requiere SPRINT_02 implementado.
func (r *adminRepo) GetCurrentMAU(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// SetOnboardingCompleted implementa AdminRepository.SetOnboardingCompleted.
// FS store: no-op, campo no persiste en YAML (cloud-only).
func (r *adminRepo) SetOnboardingCompleted(_ context.Context, _ string, _ bool) error {
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Refresh Tokens Repository
// ═══════════════════════════════════════════════════════════════════════════════

// adminRefreshTokenRepo implementa repository.AdminRefreshTokenRepository usando FileSystem.
// Los tokens se almacenan en: <fsRoot>/admins/refresh_tokens.yaml
type adminRefreshTokenRepo struct {
	fsRoot string
	mu     sync.RWMutex
}

// newAdminRefreshTokenRepo crea un nuevo repositorio de refresh tokens basado en FS.
func newAdminRefreshTokenRepo(fsRoot string) repository.AdminRefreshTokenRepository {
	return &adminRefreshTokenRepo{
		fsRoot: fsRoot,
	}
}

// refreshTokensFile estructura del archivo refresh_tokens.yaml
type refreshTokensFile struct {
	Tokens []repository.AdminRefreshToken `yaml:"refresh_tokens"`
}

// getRefreshTokensPath retorna la ruta al archivo refresh_tokens.yaml
func (r *adminRefreshTokenRepo) getRefreshTokensPath() string {
	return filepath.Join(r.fsRoot, "admins", "refresh_tokens.yaml")
}

// readTokens lee todos los tokens del archivo
func (r *adminRefreshTokenRepo) readTokens() ([]repository.AdminRefreshToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	path := r.getRefreshTokensPath()

	// Si el archivo no existe, retornar lista vacía
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []repository.AdminRefreshToken{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh tokens file: %w", err)
	}

	var file refreshTokensFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse refresh tokens file: %w", err)
	}

	return file.Tokens, nil
}

// writeTokens escribe todos los tokens al archivo
func (r *adminRefreshTokenRepo) writeTokens(tokens []repository.AdminRefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Asegurar que el directorio existe
	adminsDir := filepath.Join(r.fsRoot, "admins")
	if err := os.MkdirAll(adminsDir, 0755); err != nil {
		return fmt.Errorf("failed to ensure admins directory: %w", err)
	}

	file := refreshTokensFile{
		Tokens: tokens,
	}

	data, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh tokens: %w", err)
	}

	path := r.getRefreshTokensPath()

	// Escribir atómicamente
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// GetByTokenHash implementa AdminRefreshTokenRepository.GetByTokenHash
func (r *adminRefreshTokenRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*repository.AdminRefreshToken, error) {
	tokens, err := r.readTokens()
	if err != nil {
		return nil, err
	}

	for _, token := range tokens {
		if token.TokenHash == tokenHash {
			return &token, nil
		}
	}

	return nil, repository.ErrNotFound
}

// ListByAdminID implementa AdminRefreshTokenRepository.ListByAdminID
func (r *adminRefreshTokenRepo) ListByAdminID(ctx context.Context, adminID string) ([]repository.AdminRefreshToken, error) {
	tokens, err := r.readTokens()
	if err != nil {
		return nil, err
	}

	var filtered []repository.AdminRefreshToken
	for _, token := range tokens {
		if token.AdminID == adminID {
			filtered = append(filtered, token)
		}
	}

	return filtered, nil
}

// Create implementa AdminRefreshTokenRepository.Create
func (r *adminRefreshTokenRepo) Create(ctx context.Context, input repository.CreateAdminRefreshTokenInput) error {
	if input.AdminID == "" || input.TokenHash == "" {
		return repository.ErrInvalidInput
	}

	tokens, err := r.readTokens()
	if err != nil {
		return err
	}

	// Verificar que el hash no exista
	for _, token := range tokens {
		if token.TokenHash == input.TokenHash {
			return repository.ErrConflict
		}
	}

	// Crear token
	token := repository.AdminRefreshToken{
		TokenHash: input.TokenHash,
		AdminID:   input.AdminID,
		ExpiresAt: input.ExpiresAt,
		CreatedAt: time.Now(),
	}

	tokens = append(tokens, token)

	return r.writeTokens(tokens)
}

// Delete implementa AdminRefreshTokenRepository.Delete
func (r *adminRefreshTokenRepo) Delete(ctx context.Context, tokenHash string) error {
	tokens, err := r.readTokens()
	if err != nil {
		return err
	}

	found := false
	var filtered []repository.AdminRefreshToken

	for _, token := range tokens {
		if token.TokenHash == tokenHash {
			found = true
			continue
		}
		filtered = append(filtered, token)
	}

	if !found {
		return repository.ErrNotFound
	}

	return r.writeTokens(filtered)
}

// DeleteByAdminID implementa AdminRefreshTokenRepository.DeleteByAdminID
func (r *adminRefreshTokenRepo) DeleteByAdminID(ctx context.Context, adminID string) (int, error) {
	tokens, err := r.readTokens()
	if err != nil {
		return 0, err
	}

	var filtered []repository.AdminRefreshToken
	count := 0

	for _, token := range tokens {
		if token.AdminID == adminID {
			count++
			continue
		}
		filtered = append(filtered, token)
	}

	if count > 0 {
		if err := r.writeTokens(filtered); err != nil {
			return 0, err
		}
	}

	return count, nil
}

// DeleteExpired implementa AdminRefreshTokenRepository.DeleteExpired
func (r *adminRefreshTokenRepo) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	tokens, err := r.readTokens()
	if err != nil {
		return 0, err
	}

	var filtered []repository.AdminRefreshToken
	count := 0

	for _, token := range tokens {
		if token.ExpiresAt.Before(now) {
			count++
			continue
		}
		filtered = append(filtered, token)
	}

	if count > 0 {
		if err := r.writeTokens(filtered); err != nil {
			return 0, err
		}
	}

	return count, nil
}
