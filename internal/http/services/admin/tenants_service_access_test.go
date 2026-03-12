package admin

import (
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/jwt"
)

func TestFilterTenantsByAdminClaims(t *testing.T) {
	source := []repository.Tenant{
		{ID: "11111111-1111-1111-1111-111111111111", Slug: "acme"},
		{ID: "22222222-2222-2222-2222-222222222222", Slug: "globex"},
	}

	t.Run("fails closed without claims", func(t *testing.T) {
		filtered := filterTenantsByAdminClaims(source, nil)
		if len(filtered) != 0 {
			t.Fatalf("expected 0 tenants, got %d", len(filtered))
		}
	})

	t.Run("global admin without assignments sees none", func(t *testing.T) {
		filtered := filterTenantsByAdminClaims(source, &jwt.AdminAccessClaims{AdminType: "global"})
		if len(filtered) != 0 {
			t.Fatalf("expected 0 tenants, got %d", len(filtered))
		}
	})

	t.Run("global admin with explicit assignments is filtered", func(t *testing.T) {
		filtered := filterTenantsByAdminClaims(source, &jwt.AdminAccessClaims{
			AdminType: "global",
			Tenants:   []jwt.TenantAccessClaim{{Slug: "acme", Role: "owner"}},
		})
		if len(filtered) != 1 || filtered[0].Slug != "acme" {
			t.Fatalf("expected only acme tenant, got %+v", filtered)
		}
	})

	t.Run("wildcard assignment sees all", func(t *testing.T) {
		filtered := filterTenantsByAdminClaims(source, &jwt.AdminAccessClaims{
			AdminType: "global",
			Tenants:   []jwt.TenantAccessClaim{{Slug: "*", Role: "owner"}},
		})
		if len(filtered) != len(source) {
			t.Fatalf("expected %d tenants, got %d", len(source), len(filtered))
		}
	})

	t.Run("tenant admin filtered by slug", func(t *testing.T) {
		filtered := filterTenantsByAdminClaims(source, &jwt.AdminAccessClaims{
			AdminType: "tenant",
			Tenants:   []jwt.TenantAccessClaim{{Slug: "acme", Role: "owner"}},
		})
		if len(filtered) != 1 || filtered[0].Slug != "acme" {
			t.Fatalf("expected only acme tenant, got %+v", filtered)
		}
	})

	t.Run("tenant admin filtered by id", func(t *testing.T) {
		filtered := filterTenantsByAdminClaims(source, &jwt.AdminAccessClaims{
			AdminType: "tenant",
			Tenants:   []jwt.TenantAccessClaim{{Slug: "22222222-2222-2222-2222-222222222222", Role: "owner"}},
		})
		if len(filtered) != 1 || filtered[0].Slug != "globex" {
			t.Fatalf("expected only globex tenant by id, got %+v", filtered)
		}
	})
}
