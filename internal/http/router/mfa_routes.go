package router

import (
	"net/http"

	authctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/auth"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	storev2 "github.com/dropDatabas3/hellojohn/internal/store"
)

// MFARouterDeps contiene las dependencias para el router MFA.
type MFARouterDeps struct {
	MFATOTPController   *authctrl.MFATOTPController
	MFASMSController    *authctrl.MFASMSController
	MFAEmailController  *authctrl.MFAEmailController
	MFAFactorController *authctrl.MFAFactorController
	DAL                 storev2.DataAccessLayer // Required for tenant resolution
	RateLimiter         mw.RateLimiter          // Rate limiter opcional
	AuthMiddleware      mw.Middleware           // RequireAuth middleware (valida JWT)
}

// RegisterMFARoutes registra rutas MFA V2.
// Estas rutas requieren usuario autenticado (via JWT).
func RegisterMFARoutes(mux *http.ServeMux, deps MFARouterDeps) {
	if deps.MFATOTPController == nil &&
		deps.MFASMSController == nil &&
		deps.MFAEmailController == nil &&
		deps.MFAFactorController == nil {
		return // MFA not configured
	}

	if c := deps.MFATOTPController; c != nil {
		// POST /v2/mfa/totp/enroll - Start TOTP enrollment
		mux.Handle("/v2/mfa/totp/enroll", mfaHandler(deps, http.HandlerFunc(c.Enroll), true))

		// POST /v2/mfa/totp/verify - Confirm TOTP enrollment
		mux.Handle("/v2/mfa/totp/verify", mfaHandler(deps, http.HandlerFunc(c.Verify), true))

		// POST /v2/mfa/totp/challenge - Complete MFA challenge (no JWT auth, mfa_token driven)
		mux.Handle("/v2/mfa/totp/challenge", mfaHandler(deps, http.HandlerFunc(c.Challenge), false))

		// POST /v2/mfa/totp/disable - Disable TOTP (requires password + 2FA)
		mux.Handle("/v2/mfa/totp/disable", mfaHandler(deps, http.HandlerFunc(c.Disable), true))

		// POST /v2/mfa/recovery/rotate - Rotate recovery codes (requires password + 2FA)
		mux.Handle("/v2/mfa/recovery/rotate", mfaHandler(deps, http.HandlerFunc(c.RotateRecovery), true))
	}

	if c := deps.MFASMSController; c != nil {
		// POST /v2/mfa/sms/send - Send SMS OTP (mfa_token driven)
		mux.Handle("/v2/mfa/sms/send", mfaHandler(deps, http.HandlerFunc(c.Send), false))

		// POST /v2/mfa/sms/challenge - Verify SMS OTP challenge (mfa_token driven)
		mux.Handle("/v2/mfa/sms/challenge", mfaHandler(deps, http.HandlerFunc(c.Challenge), false))
	}

	if c := deps.MFAEmailController; c != nil {
		// POST /v2/mfa/email/send - Send Email OTP (mfa_token driven)
		mux.Handle("/v2/mfa/email/send", mfaHandler(deps, http.HandlerFunc(c.Send), false))

		// POST /v2/mfa/email/challenge - Verify Email OTP challenge (mfa_token driven)
		mux.Handle("/v2/mfa/email/challenge", mfaHandler(deps, http.HandlerFunc(c.Challenge), false))
	}

	if c := deps.MFAFactorController; c != nil {
		// GET /v2/mfa/factors - List factors for authenticated user
		mux.Handle("/v2/mfa/factors", mfaHandler(deps, http.HandlerFunc(c.GetFactors), true))

		// PUT /v2/mfa/factors/preference - Update preferred factor for authenticated user
		mux.Handle("/v2/mfa/factors/preference", mfaHandler(deps, http.HandlerFunc(c.UpdatePreference), true))
	}
}

// mfaHandler crea el middleware chain para endpoints MFA.
// Orden: Recover → RequestID → TenantResolution → RequireTenant → [Auth] → SecurityHeaders → NoStore → RateLimit → Logging
func mfaHandler(deps MFARouterDeps, handler http.Handler, requireAuth bool) http.Handler {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
	}

	// Tenant resolution (required for MFA)
	if deps.DAL != nil {
		chain = append(chain, mw.WithTenantResolution(deps.DAL, false)) // required, not optional
		chain = append(chain, mw.RequireTenant())
	}

	// Auth middleware (validates JWT, sets claims in context)
	if requireAuth && deps.AuthMiddleware != nil {
		chain = append(chain, deps.AuthMiddleware)
	}

	chain = append(chain,
		mw.WithSecurityHeaders(),
		mw.WithNoStore(), // MFA responses contain sensitive data
	)

	// Rate limiting por IP si está configurado
	if deps.RateLimiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: deps.RateLimiter,
			KeyFunc: mw.IPOnlyRateKey,
		}))
	}

	// Logging al final
	chain = append(chain, mw.WithLogging())

	return mw.Chain(handler, chain...)
}
