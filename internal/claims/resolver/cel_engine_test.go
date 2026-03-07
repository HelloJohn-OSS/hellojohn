package resolver

import (
	"context"
	"strings"
	"testing"
)

func TestCELEngine_Compilation(t *testing.T) {
	engine, err := NewCELEngine()
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	tests := []struct {
		name       string
		expression string
		wantErr    bool
	}{
		{"valid boolean operation", "input.Email == 'admin@example.com'", false},
		{"valid deep nested attribute", "input.UserMeta.tenant_status == 'active'", false},
		{"invalid syntax missing quote", "input.Email == 'admin", true},
		{"invalid undeclared variable", "unauthorized_variable == 10", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := engine.Compile(tc.expression)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for syntax '%s' but got none", tc.expression)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for syntax '%s': %v", tc.expression, err)
			}
		})
	}
}

func TestExpressionResolver_Resolve(t *testing.T) {
	engine, _ := NewCELEngine()
	ctx := context.Background()

	input := ResolverInput{
		UserID:   "admin-123",
		Email:    "hero@dev.com",
		TenantID: "system",
		Scopes:   []string{"openid", "profile"},
		Roles:    []string{"admin", "superuser"},
		UserMeta: map[string]any{
			"reputation":     int64(99),
			"account_status": "premium",
		},
	}

	tests := []struct {
		name       string
		expression string
		expected   any
		wantErr    bool
	}{
		{"email direct comparison", "input.Email == 'hero@dev.com'", true, false},
		{"string manipulation", "input.Email.startsWith('hero')", true, false},
		{"nested dict metadata validation", "input.UserMeta.account_status == 'premium'", true, false},
		{"roles array presence", "'admin' in input.Roles", true, false},
		{"math reputation logic", "input.UserMeta.reputation > 50", true, false},
		{"concatenation output", "input.TenantID + ':' + input.UserID", "system:admin-123", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Phase 1: Compile AST in load time Context.
			program, err := engine.Compile(tc.expression)
			if err != nil {
				t.Fatalf("Setup Failed compilation: %v", err)
			}

			// Phase 2: Inject to Resolver and test at Request-Time Context.
			resolver := NewExpressionResolver(program)
			if resolver.Name() != "expression" {
				t.Errorf("expected expression resolver name")
			}

			val, err := resolver.Resolve(ctx, input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected evaluation error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected execution error: %v", err)
			}

			if val != tc.expected {
				t.Errorf("expected result [%v] but got [%v]", tc.expected, val)
			}
		})
	}

	t.Run("Timeboxing DoS Safety - Timeout context", func(t *testing.T) {
		// Mock a timeout scenario where context is already expired
		program, _ := engine.Compile("input.Email == 'hero@dev.com'")
		resolver := NewExpressionResolver(program)

		// Usamos un context nativo pre-expirado (Timeout en el pasado inminente)
		// Para que el WithTimeout de 50ms de Resolve lo herede como ya cancelado.
		deadCtx, cancel := context.WithCancel(ctx)
		cancel() // Esto asegura que evalCtx.Err() devolverá "context canceled" en el hijo, o DeadlineExceeded si fuera por Time.

		_, err := resolver.Resolve(deadCtx, input)
		if err == nil {
			t.Errorf("expected specific Timebox CEL error, got: nil")
		} else if !strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "timed out") {
			// Dependiendo de la jerarquía de cancelación temprana en cel-go puede decir canceled o timeout
			// lo importante es que el AST aborte de forma defensiva.
			t.Errorf("expected timeout defensive abort, got native error: %v", err)
		}
	})
}
