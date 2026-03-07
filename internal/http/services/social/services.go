// Package social contiene los services del dominio social login.
package social

import (
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Deps contiene las dependencias para crear los services social.
type Deps struct {
	DAL            store.DataAccessLayer // V2 data access layer
	Cache          CacheWriter           // Cache with write capabilities (Get/Delete/Set)
	DebugPeek      bool                  // Enable peek mode for result viewer (should be false in production)
	StateSigner    StateSigner           // Optional: signer for state JWTs
	LoginCodeTTL   time.Duration         // TTL for login codes (default 60s)
	Registry       *Registry             // Provider registry (replaces OIDCFactory)
	Issuer         *jwt.Issuer           // JWT issuer for token signing
	BaseURL        string                // Base URL for issuer resolution
	RefreshTTL     time.Duration         // TTL for refresh tokens
	TenantProvider TenantProvider        // Control plane tenant provider
	AuditBus       *audit.AuditBus
}

// Services agrupa todos los services del dominio social.
type Services struct {
	Exchange     ExchangeService
	Result       ResultService
	Start        StartService
	Callback     CallbackService
	Provisioning ProvisioningService
	Token        TokenService
	ClientConfig ClientConfigService
	StateSigner  StateSigner // Exposed for controller-level error redirects
}

// NewServices crea el agregador de services social.
func NewServices(d Deps) Services {
	var genericOIDC GenericOIDCResolver
	if d.TenantProvider != nil {
		genericOIDC = &GenericOIDCFactory{TenantProvider: d.TenantProvider}
	}

	provisioning := NewProvisioningService(ProvisioningDeps{
		DAL: d.DAL,
	})

	tokenSvc := NewTokenService(TokenDeps{
		DAL:        d.DAL,
		Issuer:     d.Issuer,
		BaseURL:    d.BaseURL,
		RefreshTTL: d.RefreshTTL,
	})

	// ClientConfigService for validating clients/redirects/providers.
	var clientConfig ClientConfigService
	if d.TenantProvider != nil {
		clientConfig = NewClientConfigService(ClientConfigDeps{
			TenantProvider: d.TenantProvider,
		})
	}

	return Services{
		Exchange: NewExchangeService(ExchangeDeps{
			Cache:        d.Cache, // CacheWriter implements Cache
			ClientConfig: clientConfig,
		}),
		Result: NewResultService(ResultDeps{
			Cache:     d.Cache, // CacheWriter implements Cache
			DebugPeek: d.DebugPeek,
		}),
		Provisioning: provisioning,
		Token:        tokenSvc,
		ClientConfig: clientConfig,
		StateSigner:  d.StateSigner,
		Start: NewStartService(StartDeps{
			StateSigner:  d.StateSigner,
			Registry:     d.Registry,
			GenericOIDC:  genericOIDC,
			ClientConfig: clientConfig,
		}),
		Callback: NewCallbackService(CallbackDeps{
			StateSigner:  d.StateSigner,
			Cache:        d.Cache,
			LoginCodeTTL: d.LoginCodeTTL,
			Registry:     d.Registry,
			GenericOIDC:  genericOIDC,
			Provisioning: provisioning,
			TokenService: tokenSvc,
			ClientConfig: clientConfig,
			AuditBus: d.AuditBus,
		}),
	}
}
