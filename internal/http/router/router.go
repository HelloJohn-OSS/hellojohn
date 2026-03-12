// Package router contains the V2 route aggregator.
package router

import (
	"net/http"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	adminctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/admin"
	authctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/auth"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	storev2 "github.com/dropDatabas3/hellojohn/internal/store"

	// Domains
	cloudctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/cloud"
	emailctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/email"
	healthctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/health"
	oauthctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/oauth"
	oidcctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/oidc"
	securityctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/security"
	sessionctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/session"
	socialctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/social"
	sysctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/system"
)

// V2RouterDeps contains all dependencies for the V2 router.
type V2RouterDeps struct {
	Mux *http.ServeMux

	// Data access
	DAL storev2.DataAccessLayer

	// Controllers
	AuthControllers     *authctrl.Controllers
	AdminControllers    *adminctrl.Controllers
	OAuthControllers    *oauthctrl.Controllers
	OIDCControllers     *oidcctrl.Controllers
	SocialControllers   *socialctrl.Controllers
	SessionControllers  *sessionctrl.Controllers
	EmailControllers    *emailctrl.Controllers
	SecurityControllers *securityctrl.Controllers
	HealthControllers   *healthctrl.Controllers
	SystemControllers   *sysctrl.Controllers   // SA.2: System Management
	CloudControllers    *cloudctrl.Controllers // Cloud Control Plane (nil si no configurado)

	// JWT
	Issuer *jwtx.Issuer

	// Middlewares
	AuthMiddleware         mw.Middleware  // JWT validation middleware
	RateLimiter            mw.RateLimiter // Optional rate limiter
	MailingTestRateLimiter mw.RateLimiter // Tenant mailing test: max 5/min per tenant

	// Admin Config (from GlobalConfig, no env reads in router)
	AdminConfig mw.AdminConfig

	// API Key Auth (optional, enables X-API-Key header for admin routes)
	APIKeyRepo repository.APIKeyRepository
}

// RegisterV2Routes registers all V2 routes.
// This is the main entry point for V2 routing.
// Call this from app.go or equivalent main wiring file.
func RegisterV2Routes(deps V2RouterDeps) {
	mux := deps.Mux
	if mux == nil {
		return
	}

	// ===========================================================================
	// MFA Routes
	// ===========================================================================
	if deps.AuthControllers != nil && (deps.AuthControllers.MFATOTP != nil ||
		deps.AuthControllers.MFASMS != nil ||
		deps.AuthControllers.MFAEmail != nil ||
		deps.AuthControllers.MFAFactors != nil) {
		RegisterMFARoutes(mux, MFARouterDeps{
			MFATOTPController:   deps.AuthControllers.MFATOTP,
			MFASMSController:    deps.AuthControllers.MFASMS,
			MFAEmailController:  deps.AuthControllers.MFAEmail,
			MFAFactorController: deps.AuthControllers.MFAFactors,
			DAL:                 deps.DAL,
			RateLimiter:         deps.RateLimiter,
			AuthMiddleware:      deps.AuthMiddleware,
		})
	}

	// ===========================================================================
	// Admin Routes
	// ===========================================================================
	if deps.AdminControllers != nil {
		RegisterAdminRoutes(mux, AdminRouterDeps{
			DAL:                    deps.DAL,
			Issuer:                 deps.Issuer,
			Controllers:            deps.AdminControllers,
			RateLimiter:            deps.RateLimiter,
			MailingTestRateLimiter: deps.MailingTestRateLimiter,
			AdminConfig:            deps.AdminConfig,
			APIKeyRepo:             deps.APIKeyRepo,
		})
	}

	// ===========================================================================
	// Public Health Routes
	// ===========================================================================
	if deps.HealthControllers != nil {
		RegisterHealthRoutes(mux, HealthRouterDeps{
			Controllers: deps.HealthControllers,
		})
	}

	// ===========================================================================
	// Auth Routes (Login, Register, etc)
	// ===========================================================================
	if deps.AuthControllers != nil {
		RegisterAuthRoutes(mux, AuthRouterDeps{
			Controllers: deps.AuthControllers,
			RateLimiter: deps.RateLimiter,
			Issuer:      deps.Issuer,
			DAL:         deps.DAL,
		})
	}

	// ===========================================================================
	// OIDC Routes (Discovery, JWKS, UserInfo)
	// ===========================================================================
	if deps.OIDCControllers != nil {
		RegisterOIDCRoutes(mux, OIDCRouterDeps{
			Controllers: deps.OIDCControllers,
			Issuer:      deps.Issuer,
			RateLimiter: deps.RateLimiter,
		})
	}

	// ===========================================================================
	// OAuth Routes (Authorize, Token, Revoke, Introspect)
	// ===========================================================================
	if deps.OAuthControllers != nil {
		RegisterOAuthRoutes(mux, OAuthRouterDeps{
			Controllers: deps.OAuthControllers,
			RateLimiter: deps.RateLimiter,
		})
	}

	// ===========================================================================
	// Social Routes (Exchange, Providers, etc)
	// ===========================================================================
	if deps.SocialControllers != nil {
		RegisterSocialRoutes(mux, SocialRouterDeps{
			Controllers: deps.SocialControllers,
			RateLimiter: deps.RateLimiter,
		})
	}

	// ===========================================================================
	// Session Routes (Login, Logout cookies)
	// ===========================================================================
	if deps.SessionControllers != nil {
		RegisterSessionRoutes(mux, SessionRouterDeps{
			Controllers: deps.SessionControllers,
			RateLimiter: deps.RateLimiter,
			DAL:         deps.DAL,
		})
	}

	// ===========================================================================
	// Email Routes (Verify, Forgot/Reset)
	// ===========================================================================
	if deps.EmailControllers != nil {
		RegisterEmailRoutes(mux, EmailRouterDeps{
			Controllers: deps.EmailControllers,
			DAL:         deps.DAL,
			RateLimiter: deps.RateLimiter,
		})
	}

	// ===========================================================================
	// Security Routes (CSRF)
	// ===========================================================================
	if deps.SecurityControllers != nil {
		RegisterSecurityRoutes(mux, SecurityRouterDeps{
			Controllers: deps.SecurityControllers,
			RateLimiter: deps.RateLimiter,
		})
	}

	// ===========================================================================
	// System Routes (SA.2: status + sync — admin auth, no tenant scope)
	// ===========================================================================
	if deps.SystemControllers != nil {
		RegisterSystemRoutes(mux, SystemRouterDeps{
			Controllers: deps.SystemControllers,
			Issuer:      deps.Issuer,
			RateLimiter: deps.RateLimiter,
			APIKeyRepo:  deps.APIKeyRepo, // enables X-API-Key for remote instance access via proxy
		})
	}

	// ===========================================================================
	// Cloud Routes (Cloud Control Plane — public OIDC flow + protected CRUD)
	// ===========================================================================
	if deps.CloudControllers != nil {
		RegisterCloudRoutes(mux, CloudRouterDeps{
			Controllers: deps.CloudControllers,
			Issuer:      deps.Issuer,
		})
	}
}
