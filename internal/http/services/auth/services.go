// Package auth contiene los services de autenticación V2.
package auth

import (
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	bot "github.com/dropDatabas3/hellojohn/internal/http/services/bot"
	socialsvc "github.com/dropDatabas3/hellojohn/internal/http/services/social"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	adaptive "github.com/dropDatabas3/hellojohn/internal/mfa/adaptive"
	smspkg "github.com/dropDatabas3/hellojohn/internal/mfa/sms"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Deps contiene las dependencias para crear los services auth.
type Deps struct {
	DAL                         store.DataAccessLayer
	Issuer                      *jwtx.Issuer
	Cache                       cache.Client
	SessionCache                cache.Client
	RefreshTTL                  time.Duration
	ReuseDetection              bool
	ClaimsHook                  ClaimsHook      // nil = NoOp
	BlacklistPath               string          // Password blacklist path (optional)
	AutoLogin                   bool            // Auto-login after registration
	FSAdminEnabled              bool            // Allow FS-admin registration
	DataRoot                    string          // Data root for logo file reading
	Providers                   ProviderConfig  // Global provider configuration
	Email                       emailv2.Service // Email service for verification
	Social                      socialsvc.Services
	MFATOTPWindow               int    // TOTP validation window (±N)
	MFATOTPIssuer               string // TOTP app display name
	MFASMSProvider              string
	MFASMSPhoneField            string
	MFASMSOTPLength             int
	MFASMSOTPTTL                time.Duration
	MFASMSRateLimitHourly       int
	MFASMSTwilioAccountSID      string
	MFASMSTwilioAuthToken       string
	MFASMSTwilioFrom            string
	MFASMSVonageAPIKey          string
	MFASMSVonageAPISecret       string
	MFASMSVonageFrom            string
	MFAEmailOTPLength           int
	MFAEmailOTPTTL              time.Duration
	MFAEmailRateLimitHourly     int
	MFAEmailSubject             string
	MFAPreferredFactorField     string
	MFAAdaptiveEnabled          bool
	MFAAdaptiveRules            []string
	MFAAdaptiveFailureThreshold int
	MFAAdaptiveStateTTL         time.Duration
	BaseURL                     string // URL base para construir links
	AuditBus                    *audit.AuditBus

	// BotProtection para validación anti-bot en login y registro.
	// Si nil, se usa NoopService (no hay validación).
	BotProtection bot.BotProtectionService

	// Password Policy fallback chain configuration.
	PasswordPolicyGlobalTenant string
	PasswordPolicyEnv          *repository.SecurityPolicy
}

// Services agrupa todos los services del dominio auth.
type Services struct {
	Login            LoginService
	Refresh          RefreshService
	Logout           LogoutService
	Register         RegisterService
	InvitationAccept InvitationAcceptService
	WebAuthn         WebAuthnAuthService
	Config           ConfigService
	Providers        ProvidersService
	CompleteProfile  CompleteProfileService
	Profile          ProfileService
	MFATOTP          MFATOTPService
	MFASMS           MFASMSService
	MFAEmail         MFAEmailService
	MFAFactors       MFAFactorService
	Passwordless     PasswordlessService
	Social           socialsvc.Services
}

// NewServices crea el agregador de services auth.
func NewServices(d Deps) Services {
	adaptiveCfg := adaptive.Config{
		Enabled:          d.MFAAdaptiveEnabled,
		Rules:            d.MFAAdaptiveRules,
		FailureThreshold: d.MFAAdaptiveFailureThreshold,
		StateTTL:         d.MFAAdaptiveStateTTL,
	}.Normalize()
	adaptiveEngine := adaptive.NewEngine()

	var smsProvider smspkg.SMSProvider
	if p, err := smspkg.NewProvider(smspkg.Config{
		Provider:         d.MFASMSProvider,
		TwilioAccountSID: d.MFASMSTwilioAccountSID,
		TwilioAuthToken:  d.MFASMSTwilioAuthToken,
		TwilioFrom:       d.MFASMSTwilioFrom,
		VonageAPIKey:     d.MFASMSVonageAPIKey,
		VonageAPISecret:  d.MFASMSVonageAPISecret,
		VonageFrom:       d.MFASMSVonageFrom,
		Timeout:          10 * time.Second,
	}); err == nil {
		smsProvider = p
	}
	smsGlobalAvailable := smsProvider != nil

	return Services{
		Login: NewLoginService(LoginDeps{
			DAL:                  d.DAL,
			Issuer:               d.Issuer,
			RefreshTTL:           d.RefreshTTL,
			ClaimsHook:           d.ClaimsHook,
			PhoneField:           d.MFASMSPhoneField,
			PreferredFactorField: d.MFAPreferredFactorField,
			SMSGlobalAvailable:   smsGlobalAvailable,
			AdaptiveConfig:       adaptiveCfg,
			AdaptiveEngine:       adaptiveEngine,
			AuditBus:             d.AuditBus,
			BotProtection:        d.BotProtection,
		}),
		Refresh: NewRefreshService(RefreshDeps{
			DAL:                   d.DAL,
			Issuer:                d.Issuer,
			RefreshTTL:            d.RefreshTTL,
			ReuseDetectionEnabled: d.ReuseDetection,
			ClaimsHook:            d.ClaimsHook,
		}),
		Logout: NewLogoutService(LogoutDeps{
			DAL:          d.DAL,
			SessionCache: d.SessionCache,
		}),
		Register: NewRegisterService(RegisterDeps{
			DAL:                        d.DAL,
			Issuer:                     d.Issuer,
			RefreshTTL:                 d.RefreshTTL,
			ClaimsHook:                 d.ClaimsHook,
			BlacklistPath:              d.BlacklistPath,
			AutoLogin:                  d.AutoLogin,
			FSAdminEnabled:             d.FSAdminEnabled,
			VerificationSender:         EmailVerificationSender{Email: d.Email},
			AuditBus:                   d.AuditBus,
			BotProtection:              d.BotProtection,
			PasswordPolicyGlobalTenant: d.PasswordPolicyGlobalTenant,
			PasswordPolicyEnv:          d.PasswordPolicyEnv,
		}),
		InvitationAccept: NewInvitationAcceptService(InvitationAcceptDeps{
			DAL:        d.DAL,
			Issuer:     d.Issuer,
			RefreshTTL: d.RefreshTTL,
			ClaimsHook: d.ClaimsHook,
		}),
		WebAuthn: NewWebAuthnAuthService(WebAuthnDeps{
			DAL:        d.DAL,
			Issuer:     d.Issuer,
			RefreshTTL: d.RefreshTTL,
			ClaimsHook: d.ClaimsHook,
			BaseURL:    d.BaseURL,
		}),
		Config: NewConfigService(ConfigDeps{
			DAL:                        d.DAL,
			DataRoot:                   d.DataRoot,
			BotProtection:              d.BotProtection,
			PasswordPolicyGlobalTenant: d.PasswordPolicyGlobalTenant,
			PasswordPolicyEnv:          d.PasswordPolicyEnv,
		}),
		Providers: NewProvidersService(ProvidersDeps{
			DAL:       d.DAL,
			Providers: d.Providers,
		}),
		CompleteProfile: NewCompleteProfileService(CompleteProfileDeps{
			DAL: d.DAL,
		}),
		Profile: NewProfileService(ProfileDeps{
			DAL: d.DAL,
		}),
		MFATOTP: NewMFATOTPService(MFATOTPDeps{
			DAL:              d.DAL,
			Issuer:           d.Issuer,
			Cache:            d.Cache,
			RefreshTTL:       d.RefreshTTL,
			ClaimsHook:       d.ClaimsHook,
			TOTPWindow:       d.MFATOTPWindow,
			TOTPIssuer:       d.MFATOTPIssuer,
			AdaptiveStateTTL: adaptiveCfg.StateTTL,
			AuditBus:         d.AuditBus,
		}),
		MFASMS: NewMFASMSService(MFASMSDeps{
			DAL:              d.DAL,
			Issuer:           d.Issuer,
			RefreshTTL:       d.RefreshTTL,
			ClaimsHook:       d.ClaimsHook,
			Provider:         smsProvider,
			PhoneField:       d.MFASMSPhoneField,
			OTPLength:        d.MFASMSOTPLength,
			OTPTTL:           d.MFASMSOTPTTL,
			RateLimitHourly:  d.MFASMSRateLimitHourly,
			AdaptiveStateTTL: adaptiveCfg.StateTTL,
			AuditBus:         d.AuditBus,
		}),
		MFAEmail: NewMFAEmailService(MFAEmailDeps{
			DAL:              d.DAL,
			Issuer:           d.Issuer,
			Email:            d.Email,
			RefreshTTL:       d.RefreshTTL,
			ClaimsHook:       d.ClaimsHook,
			OTPLength:        d.MFAEmailOTPLength,
			OTPTTL:           d.MFAEmailOTPTTL,
			RateLimitHourly:  d.MFAEmailRateLimitHourly,
			Subject:          d.MFAEmailSubject,
			AdaptiveStateTTL: adaptiveCfg.StateTTL,
			AuditBus:         d.AuditBus,
		}),
		MFAFactors: NewMFAFactorService(MFAFactorDeps{
			DAL:                  d.DAL,
			PhoneField:           d.MFASMSPhoneField,
			PreferredFactorField: d.MFAPreferredFactorField,
			SMSGlobalAvailable:   smsGlobalAvailable,
		}),
		Passwordless: NewPasswordlessService(PasswordlessDeps{
			DAL:        d.DAL,
			Issuer:     d.Issuer,
			Cache:      d.Cache,
			RefreshTTL: d.RefreshTTL,
			Email:      d.Email,
			BaseURL:    d.BaseURL,
			AuditBus:   d.AuditBus,
		}),
		Social: d.Social,
	}
}
