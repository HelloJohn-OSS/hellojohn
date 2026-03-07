package clusterv2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// Applier es la interfaz para aplicar mutaciones en Store V2.
type Applier interface {
	Apply(m Mutation) error
}

// ConfigAccessor provee acceso a repos de control plane.
type ConfigAccessor interface {
	Tenants() repository.TenantRepository
	Clients(tenantSlug string) repository.ClientRepository
	Scopes(tenantSlug string) repository.ScopeRepository
	Claims(tenantSlug string) repository.ClaimRepository
}

// V2Applier implementa Applier usando Store V2.
type V2Applier struct {
	config ConfigAccessor
	fsRoot string // FS root para operaciones de keys
}

// NewV2Applier crea un Applier que usa Store V2.
func NewV2Applier(config ConfigAccessor, fsRoot string) *V2Applier {
	return &V2Applier{config: config, fsRoot: fsRoot}
}

// Apply aplica una mutación al Store V2.
// Determinístico: no genera IDs ni timestamps, solo escribe datos pre-construidos.
func (a *V2Applier) Apply(m Mutation) error {
	ctx := context.Background()

	switch m.Type {
	case MutationClientCreate, MutationClientUpdate:
		return a.upsertClient(ctx, m)
	case MutationClientDelete:
		return a.deleteClient(ctx, m)
	case MutationTenantCreate, MutationTenantUpdate:
		return a.upsertTenant(ctx, m)
	case MutationTenantDelete:
		return a.deleteTenant(ctx, m)
	case MutationSettingsUpdate:
		return a.updateSettings(ctx, m)
	case MutationScopeCreate:
		return a.upsertScope(ctx, m)
	case MutationScopeDelete:
		return a.deleteScope(ctx, m)
	case MutationKeyRotate:
		return a.rotateKey(m)
	default:
		// Tipo desconocido: ignorar
		return nil
	}
}

func (a *V2Applier) upsertClient(ctx context.Context, m Mutation) error {
	var p ClientPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("unmarshal client payload: %w", err)
	}

	clientRepo := a.config.Clients(m.TenantSlug)
	if clientRepo == nil {
		return nil // no client repo disponible
	}

	input := repository.ClientInput{
		ClientID:                 p.ClientID,
		Name:                     p.Name,
		Type:                     p.Type,
		AuthProfile:              p.AuthProfile,
		Secret:                   p.Secret,
		RedirectURIs:             p.RedirectURIs,
		AllowedOrigins:           p.AllowedOrigins,
		Providers:                p.Providers,
		Scopes:                   p.Scopes,
		RequireEmailVerification: p.RequireEmailVerification,
		ResetPasswordURL:         p.ResetPasswordURL,
		VerifyEmailURL:           p.VerifyEmailURL,
		GrantTypes:               p.GrantTypes,
		AccessTokenTTL:           p.AccessTokenTTL,
		RefreshTokenTTL:          p.RefreshTokenTTL,
		IDTokenTTL:               p.IDTokenTTL,
		PostLogoutURIs:           p.PostLogoutURIs,
		Description:              p.Description,
	}

	// Intentar Get para determinar create vs update
	_, err := clientRepo.Get(ctx, p.ClientID)
	if err == repository.ErrNotFound {
		_, err = clientRepo.Create(ctx, input)
	} else if err == nil {
		_, err = clientRepo.Update(ctx, input)
	}
	return err
}

func (a *V2Applier) deleteClient(ctx context.Context, m Mutation) error {
	var p DeletePayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("unmarshal delete payload: %w", err)
	}

	clientRepo := a.config.Clients(m.TenantSlug)
	if clientRepo == nil {
		return nil
	}

	err := clientRepo.Delete(ctx, p.ID)
	if err == repository.ErrNotFound {
		return nil // Idempotent
	}
	return err
}

func (a *V2Applier) upsertTenant(ctx context.Context, m Mutation) error {
	var p TenantPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("unmarshal tenant payload: %w", err)
	}

	tenantRepo := a.config.Tenants()
	if tenantRepo == nil {
		return nil
	}

	// Deserializar settings si presente
	var settings repository.TenantSettings
	if len(p.Settings) > 0 {
		if err := json.Unmarshal(p.Settings, &settings); err != nil {
			return fmt.Errorf("unmarshal tenant settings: %w", err)
		}
	}

	tenant := &repository.Tenant{
		ID:       p.ID,
		Name:     p.Name,
		Slug:     p.Slug,
		Settings: settings,
	}

	// Verificar si existe
	_, err := tenantRepo.GetBySlug(ctx, p.Slug)
	if err == repository.ErrNotFound {
		err = tenantRepo.Create(ctx, tenant)
	} else if err == nil {
		err = tenantRepo.Update(ctx, tenant)
	}
	return err
}

func (a *V2Applier) deleteTenant(ctx context.Context, m Mutation) error {
	tenantRepo := a.config.Tenants()
	if tenantRepo == nil {
		return nil
	}

	err := tenantRepo.Delete(ctx, m.TenantSlug)
	if err == repository.ErrNotFound {
		return nil // Idempotent
	}
	return err
}

func (a *V2Applier) updateSettings(ctx context.Context, m Mutation) error {
	var p SettingsPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("unmarshal settings payload: %w", err)
	}

	tenantRepo := a.config.Tenants()
	if tenantRepo == nil {
		return nil
	}

	var settings repository.TenantSettings
	if err := json.Unmarshal(p.Settings, &settings); err != nil {
		return fmt.Errorf("unmarshal tenant settings: %w", err)
	}

	return tenantRepo.UpdateSettings(ctx, m.TenantSlug, &settings)
}

func (a *V2Applier) upsertScope(ctx context.Context, m Mutation) error {
	var p ScopePayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("unmarshal scope payload: %w", err)
	}

	scopeRepo := a.config.Scopes(m.TenantSlug)
	if scopeRepo == nil {
		return nil
	}

	input := repository.ScopeInput{
		Name:        p.Name,
		Description: p.Description,
		DisplayName: p.DisplayName,
		Claims:      p.Claims,
		DependsOn:   p.DependsOn,
		System:      p.System,
	}
	_, err := scopeRepo.Upsert(ctx, input)
	return err
}

func (a *V2Applier) deleteScope(ctx context.Context, m Mutation) error {
	var p DeletePayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("unmarshal delete payload: %w", err)
	}

	scopeRepo := a.config.Scopes(m.TenantSlug)
	if scopeRepo == nil {
		return nil
	}

	err := scopeRepo.Delete(ctx, p.ID)
	if err == repository.ErrNotFound {
		return nil
	}
	return err
}

// rotateKey escribe los blobs JSON directamente al FS.
func (a *V2Applier) rotateKey(m Mutation) error {
	if a.fsRoot == "" {
		return nil // Sin FS, no podemos rotar keys
	}

	var p KeyRotatePayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("unmarshal key rotate payload: %w", err)
	}

	// Determinar directorio: global si tenantSlug vacío, sino por tenant
	var keysDir string
	if m.TenantSlug == "" || m.TenantSlug == "global" {
		keysDir = filepath.Join(a.fsRoot, "keys")
	} else {
		keysDir = filepath.Join(a.fsRoot, "keys", m.TenantSlug)
	}
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return err
	}

	// Escribir active.json
	if strings.TrimSpace(p.ActiveJSON) != "" {
		if err := atomicWrite(filepath.Join(keysDir, "active.json"), []byte(p.ActiveJSON)); err != nil {
			return err
		}
	}

	// Escribir o eliminar retiring.json
	retPath := filepath.Join(keysDir, "retiring.json")
	if strings.TrimSpace(p.RetiringJSON) == "" {
		_ = os.Remove(retPath)
	} else {
		if err := atomicWrite(retPath, []byte(p.RetiringJSON)); err != nil {
			return err
		}
	}

	return nil
}

// atomicWrite escribe un archivo de forma atómica (tmp + rename).
// En Windows necesitamos os.Remove antes del rename porque no soporta overwrite.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// En Windows, os.Rename falla si destino existe → borrar primero
	_ = os.Remove(path)
	return os.Rename(tmp, path)
}
