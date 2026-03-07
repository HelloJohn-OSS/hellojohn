package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

func TestRBACService_CreateRole_PermissionMutationErrorReturnsFailureAndNoSuccessEvent(t *testing.T) {
	writer := &captureAuditWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()
	defer bus.Stop()

	svc := NewRBACService(bus)
	tda := &fakeRBACTenantDataAccess{
		id:   "tenant-a",
		slug: "tenant-a",
		rbac: &fakeRBACRepo{
			role: repository.Role{
				ID:        "role-1",
				Name:      "ops",
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			},
			addPermissionErr: map[string]error{
				"perm:write": errors.New("add permission failed"),
			},
		},
	}

	_, err := svc.CreateRole(context.Background(), tda, dto.CreateRoleRequest{
		Name:        "ops",
		Permissions: []string{"perm:write"},
	})
	if err == nil {
		t.Fatalf("expected error when permission assignment fails")
	}

	bus.Stop()
	events := writer.Snapshot()

	if success := findEvent(events, audit.EventRoleCreated, audit.ResultSuccess); success != nil {
		t.Fatalf("unexpected success event on partial failure: %+v", *success)
	}

	failure := findEvent(events, audit.EventRoleCreated, audit.ResultError)
	if failure == nil {
		t.Fatalf("expected role-created error event")
	}
	if got := failure.Metadata["reason"]; got != "assign_permission_failed" {
		t.Fatalf("expected reason assign_permission_failed, got %v", got)
	}
}

func TestRBACService_UpdateRole_PermissionMutationErrorReturnsFailureAndNoSuccessEvent(t *testing.T) {
	writer := &captureAuditWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()
	defer bus.Stop()

	svc := NewRBACService(bus)
	tda := &fakeRBACTenantDataAccess{
		id:   "tenant-a",
		slug: "tenant-a",
		rbac: &fakeRBACRepo{
			role: repository.Role{
				ID:        "role-1",
				Name:      "ops",
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			},
			rolePerms: []string{"perm:read"},
			addPermissionErr: map[string]error{
				"perm:write": errors.New("add permission failed"),
			},
		},
	}

	_, err := svc.UpdateRole(context.Background(), tda, "ops", dto.UpdateRoleRequest{
		Permissions: []string{"perm:read", "perm:write"},
	})
	if err == nil {
		t.Fatalf("expected error when permission update fails")
	}

	bus.Stop()
	events := writer.Snapshot()

	if success := findEvent(events, audit.EventRoleUpdated, audit.ResultSuccess); success != nil {
		t.Fatalf("unexpected success event on partial failure: %+v", *success)
	}

	failure := findEvent(events, audit.EventRoleUpdated, audit.ResultError)
	if failure == nil {
		t.Fatalf("expected role-updated error event")
	}
	if got := failure.Metadata["reason"]; got != "add_permission_failed" {
		t.Fatalf("expected reason add_permission_failed, got %v", got)
	}
}

type fakeRBACRepo struct {
	role                  repository.Role
	rolePerms             []string
	addPermissionErr      map[string]error
	removePermissionErr   map[string]error
	getRolePermissionsErr error
	getRoleUsersCountErr  error
}

func (f *fakeRBACRepo) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}

func (f *fakeRBACRepo) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}

func (f *fakeRBACRepo) AssignRole(ctx context.Context, tenantID, userID, role string) error {
	return nil
}

func (f *fakeRBACRepo) RemoveRole(ctx context.Context, tenantID, userID, role string) error {
	return nil
}

func (f *fakeRBACRepo) GetRolePermissions(ctx context.Context, tenantID, role string) ([]string, error) {
	if f.getRolePermissionsErr != nil {
		return nil, f.getRolePermissionsErr
	}
	out := make([]string, len(f.rolePerms))
	copy(out, f.rolePerms)
	return out, nil
}

func (f *fakeRBACRepo) AddPermissionToRole(ctx context.Context, tenantID, role, permission string) error {
	if err := f.addPermissionErr[permission]; err != nil {
		return err
	}
	for _, p := range f.rolePerms {
		if p == permission {
			return nil
		}
	}
	f.rolePerms = append(f.rolePerms, permission)
	return nil
}

func (f *fakeRBACRepo) RemovePermissionFromRole(ctx context.Context, tenantID, role, permission string) error {
	if err := f.removePermissionErr[permission]; err != nil {
		return err
	}
	filtered := make([]string, 0, len(f.rolePerms))
	for _, p := range f.rolePerms {
		if p != permission {
			filtered = append(filtered, p)
		}
	}
	f.rolePerms = filtered
	return nil
}

func (f *fakeRBACRepo) ListRoles(ctx context.Context, tenantID string) ([]repository.Role, error) {
	return []repository.Role{f.role}, nil
}

func (f *fakeRBACRepo) GetRole(ctx context.Context, tenantID, name string) (*repository.Role, error) {
	r := f.role
	if r.Name == "" {
		r.Name = name
	}
	return &r, nil
}

func (f *fakeRBACRepo) CreateRole(ctx context.Context, tenantID string, input repository.RoleInput) (*repository.Role, error) {
	r := f.role
	if r.ID == "" {
		r.ID = "role-1"
	}
	r.Name = input.Name
	r.Description = input.Description
	r.InheritsFrom = input.InheritsFrom
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	r.UpdatedAt = time.Now().UTC()
	f.role = r
	return &r, nil
}

func (f *fakeRBACRepo) UpdateRole(ctx context.Context, tenantID, name string, input repository.RoleInput) (*repository.Role, error) {
	r := f.role
	if r.ID == "" {
		r.ID = "role-1"
	}
	r.Name = name
	r.Description = input.Description
	r.InheritsFrom = input.InheritsFrom
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	r.UpdatedAt = time.Now().UTC()
	f.role = r
	return &r, nil
}

func (f *fakeRBACRepo) DeleteRole(ctx context.Context, tenantID, name string) error {
	return nil
}

func (f *fakeRBACRepo) GetRoleUsersCount(ctx context.Context, tenantID, role string) (int, error) {
	if f.getRoleUsersCountErr != nil {
		return 0, f.getRoleUsersCountErr
	}
	return 0, nil
}

type fakeRBACTenantDataAccess struct {
	id           string
	slug         string
	requireDBErr error
	rbac         repository.RBACRepository
}

func (f *fakeRBACTenantDataAccess) Slug() string {
	if f.slug != "" {
		return f.slug
	}
	return f.id
}

func (f *fakeRBACTenantDataAccess) ID() string {
	return f.id
}

func (f *fakeRBACTenantDataAccess) Settings() *repository.TenantSettings {
	return &repository.TenantSettings{}
}

func (f *fakeRBACTenantDataAccess) Driver() string {
	return "test"
}

func (f *fakeRBACTenantDataAccess) Users() repository.UserRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) Tokens() repository.TokenRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) MFA() repository.MFARepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) Consents() repository.ConsentRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) RBAC() repository.RBACRepository {
	return f.rbac
}

func (f *fakeRBACTenantDataAccess) Schema() repository.SchemaRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) EmailTokens() repository.EmailTokenRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) Identities() repository.IdentityRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) Sessions() repository.SessionRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) Audit() repository.AuditRepository {
	return nil
}
func (f *fakeRBACTenantDataAccess) Claims() repository.ClaimRepository { return nil }
func (f *fakeRBACTenantDataAccess) Webhooks() repository.WebhookRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) Clients() repository.ClientRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) Scopes() repository.ScopeRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) Cache() cache.Client {
	return nil
}

func (f *fakeRBACTenantDataAccess) CacheRepo() repository.CacheRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) Mailer() store.MailSender {
	return nil
}

func (f *fakeRBACTenantDataAccess) Invitations() repository.InvitationRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) WebAuthn() repository.WebAuthnRepository {
	return nil
}

func (f *fakeRBACTenantDataAccess) InfraStats(ctx context.Context) (*store.TenantInfraStats, error) {
	return nil, nil
}

func (f *fakeRBACTenantDataAccess) HasDB() bool {
	return f.requireDBErr == nil
}

func (f *fakeRBACTenantDataAccess) RequireDB() error {
	return f.requireDBErr
}
