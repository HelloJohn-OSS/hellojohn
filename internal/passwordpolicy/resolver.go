package passwordpolicy

import (
	"context"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Source indicates where the effective password policy was resolved from.
type Source string

const (
	SourceTenant             Source = "tenant"
	SourceGlobalControlPlane Source = "global_control_plane"
	SourceEnv                Source = "env"
	SourceDefault            Source = "default"
)

// ResolvedPolicy represents the effective password policy and its origin.
type ResolvedPolicy struct {
	Policy     repository.SecurityPolicy
	Source     Source
	TenantID   string
	Configured bool
}

// ResolveForTenant resolves password policy with fallback chain:
// tenant > global control plane > env > default.
func ResolveForTenant(
	ctx context.Context,
	dal store.DataAccessLayer,
	tenantID string,
	globalPolicyTenant string,
	envPolicy *repository.SecurityPolicy,
) (ResolvedPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID != "" && dal != nil {
		tda, err := dal.ForTenant(ctx, tenantID)
		if err != nil {
			return defaultResolvedPolicy(), err
		}
		if tda != nil {
			tenantPolicy := tda.Settings().Security
			if HasConfiguredRules(tenantPolicy) {
				return ResolvedPolicy{
					Policy:     EffectiveSecurityPolicy(tenantPolicy),
					Source:     SourceTenant,
					TenantID:   strings.TrimSpace(tda.ID()),
					Configured: true,
				}, nil
			}
		}
	}

	if policy := resolveGlobalPolicy(ctx, dal, globalPolicyTenant); HasConfiguredRules(policy) {
		return ResolvedPolicy{
			Policy:     EffectiveSecurityPolicy(policy),
			Source:     SourceGlobalControlPlane,
			Configured: true,
		}, nil
	}

	if HasConfiguredRules(envPolicy) {
		return ResolvedPolicy{
			Policy:     EffectiveSecurityPolicy(envPolicy),
			Source:     SourceEnv,
			Configured: true,
		}, nil
	}

	return defaultResolvedPolicy(), nil
}

// ResolveForCloud resolves password policy with fallback chain:
// global control plane > env > default.
func ResolveForCloud(
	ctx context.Context,
	dal store.DataAccessLayer,
	globalPolicyTenant string,
	envPolicy *repository.SecurityPolicy,
) ResolvedPolicy {
	if policy := resolveGlobalPolicy(ctx, dal, globalPolicyTenant); HasConfiguredRules(policy) {
		return ResolvedPolicy{
			Policy:     EffectiveSecurityPolicy(policy),
			Source:     SourceGlobalControlPlane,
			Configured: true,
		}
	}

	if HasConfiguredRules(envPolicy) {
		return ResolvedPolicy{
			Policy:     EffectiveSecurityPolicy(envPolicy),
			Source:     SourceEnv,
			Configured: true,
		}
	}

	return defaultResolvedPolicy()
}

func defaultResolvedPolicy() ResolvedPolicy {
	return ResolvedPolicy{
		Policy:     EffectiveSecurityPolicy(nil),
		Source:     SourceDefault,
		Configured: false,
	}
}

func resolveGlobalPolicy(ctx context.Context, dal store.DataAccessLayer, globalPolicyTenant string) *repository.SecurityPolicy {
	slugOrID := strings.TrimSpace(globalPolicyTenant)
	if slugOrID == "" || dal == nil {
		return nil
	}
	tda, err := dal.ForTenant(ctx, slugOrID)
	if err != nil || tda == nil {
		return nil
	}
	return tda.Settings().Security
}
