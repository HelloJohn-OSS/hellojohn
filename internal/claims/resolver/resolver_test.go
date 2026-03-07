package resolver

import (
	"context"
	"testing"
)

func TestStaticResolver(t *testing.T) {
	ctx := context.Background()
	input := ResolverInput{}

	t.Run("returns simple string", func(t *testing.T) {
		r := &StaticResolver{Value: "hello"}
		if r.Name() != "static" {
			t.Errorf("expected static name, got %s", r.Name())
		}

		val, err := r.Resolve(ctx, input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if val != "hello" {
			t.Errorf("expected hello, got %v", val)
		}
	})

	t.Run("returns map object", func(t *testing.T) {
		obj := map[string]any{"prop": true}
		r := &StaticResolver{Value: obj}

		val, _ := r.Resolve(ctx, input)
		m, ok := val.(map[string]any)
		if !ok || m["prop"] != true {
			t.Errorf("expected map with prop=true, got %v", val)
		}
	})
}

func TestUserAttributeResolver(t *testing.T) {
	ctx := context.Background()
	input := ResolverInput{
		UserID:   "user-123",
		Email:    "test@example.com",
		TenantID: "tenant-456",
		ClientID: "client-789",
		UserMeta: map[string]any{
			"company": "BananaCorp",
			"age":     30,
			"settings": map[string]any{
				"theme": "dark",
				"deep": map[string]any{
					"flag": true,
				},
			},
		},
	}

	tests := []struct {
		name     string
		field    string
		expected any
	}{
		{"empty field", "", nil},
		{"email mapping", "email", "test@example.com"},
		{"sub/userid mapping", "sub", "user-123"},
		{"user_id explicit", "user_id", "user-123"},
		{"tenant_id mapping", "tenant_id", "tenant-456"},
		{"client_id mapping", "client_id", "client-789"},
		{"shallow metadata", "metadata.company", "BananaCorp"},
		{"nested metadata", "metadata.settings.theme", "dark"},
		{"deep nested metadata", "metadata.settings.deep.flag", true},
		{"metadata missing top key", "metadata.missing", nil},
		{"metadata missing deep key", "metadata.settings.missing", nil},
		{"metadata type mismatch", "metadata.age.nested", nil}, // age is int, not map
		{"unsupported mapping", "unsupported", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &UserAttributeResolver{Field: tc.field}
			if r.Name() != "user_attribute" {
				t.Errorf("expected user_attribute name")
			}

			val, err := r.Resolve(ctx, input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if val != tc.expected {
				t.Errorf("expected %v, got %v for field %s", tc.expected, val, tc.field)
			}
		})
	}

	t.Run("nil user metadata safe extract", func(t *testing.T) {
		r := &UserAttributeResolver{Field: "metadata.company"}
		emptyInput := ResolverInput{Email: "test@x.com"}
		val, _ := r.Resolve(ctx, emptyInput)
		if val != nil {
			t.Errorf("expected safely nil, got %v", val)
		}
	})
}

func TestRBACResolver(t *testing.T) {
	ctx := context.Background()

	input := ResolverInput{
		Roles:       []string{"admin", "editor"},
		Permissions: []string{"read:logs", "write:posts"},
	}
	emptyInput := ResolverInput{}

	tests := []struct {
		name       string
		incRoles   bool
		incPerm    bool
		input      ResolverInput
		verifyFunc func(*testing.T, any)
	}{
		{
			name:     "both empty false returns nil",
			incRoles: false,
			incPerm:  false,
			input:    input,
			verifyFunc: func(t *testing.T, v any) {
				if v != nil {
					t.Errorf("expected nil")
				}
			},
		},
		{
			name:     "roles only returns string slice",
			incRoles: true,
			incPerm:  false,
			input:    input,
			verifyFunc: func(t *testing.T, v any) {
				arr, ok := v.([]string)
				if !ok || len(arr) != 2 || arr[0] != "admin" {
					t.Errorf("expected [admin, editor] slice, got %v", v)
				}
			},
		},
		{
			name:     "permissions only returns string slice",
			incRoles: false,
			incPerm:  true,
			input:    input,
			verifyFunc: func(t *testing.T, v any) {
				arr, ok := v.([]string)
				if !ok || len(arr) != 2 || arr[0] != "read:logs" {
					t.Errorf("expected [read:logs, ...] slice, got %v", v)
				}
			},
		},
		{
			name:     "both truthy returns composite map",
			incRoles: true,
			incPerm:  true,
			input:    input,
			verifyFunc: func(t *testing.T, v any) {
				m, ok := v.(map[string]any)
				if !ok {
					t.Fatalf("expected map, got %v", v)
				}
				roles, rok := m["roles"].([]string)
				perms, pok := m["permissions"].([]string)
				if !rok || !pok || len(roles) != 2 || len(perms) != 2 {
					t.Errorf("expected map of arrays, got %v", m)
				}
			},
		},
		{
			name:     "nil inputs generate empty arrays for jwt schema safety",
			incRoles: true,
			incPerm:  true,
			input:    emptyInput,
			verifyFunc: func(t *testing.T, v any) {
				m, ok := v.(map[string]any)
				if !ok {
					t.Fatalf("expected map, got %v", v)
				}
				roles, _ := m["roles"].([]string)
				perms, _ := m["permissions"].([]string)
				if len(roles) != 0 || len(perms) != 0 {
					t.Errorf("expected initialized empty slices, got %v", m)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &RBACResolver{IncludeRoles: tc.incRoles, IncludePermissions: tc.incPerm}
			if r.Name() != "rbac" {
				t.Errorf("expected rbac name")
			}
			val, err := r.Resolve(ctx, tc.input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			tc.verifyFunc(t, val)
		})
	}
}
