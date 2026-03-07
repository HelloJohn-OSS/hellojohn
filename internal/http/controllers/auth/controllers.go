// Package auth contiene los controllers de autenticación V2.
package auth

import (
	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/http/controllers/social"
	sessiondto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// ControllerDeps contains extra controller config.
type ControllerDeps struct {
	LogoutConfig sessiondto.SessionLogoutConfig
	DAL          store.DataAccessLayer
	SessionCache cache.Client
}

// Controllers agrupa todos los controllers del dominio auth.
type Controllers struct {
	Login            *LoginController
	Refresh          *RefreshController
	Logout           *LogoutController
	Register         *RegisterController
	InvitationAccept *InvitationAcceptController
	WebAuthn         *WebAuthnController
	Config           *ConfigController
	Providers        *ProvidersController
	CompleteProfile  *CompleteProfileController
	Me               *MeController
	Profile          *ProfileController
	MFATOTP          *MFATOTPController
	MFASMS           *MFASMSController
	MFAEmail         *MFAEmailController
	MFAFactors       *MFAFactorController
	Passwordless     *PasswordlessController
	Social           *social.Controllers
}

// NewControllers crea el agregador de controllers auth.
func NewControllers(s svc.Services, deps ControllerDeps) *Controllers {
	return &Controllers{
		Login:            NewLoginController(s.Login),
		Refresh:          NewRefreshController(s.Refresh),
		Logout:           NewLogoutController(s.Logout, deps.LogoutConfig, deps.DAL, deps.SessionCache),
		Register:         NewRegisterController(s.Register),
		InvitationAccept: NewInvitationAcceptController(s.InvitationAccept),
		WebAuthn:         NewWebAuthnController(s.WebAuthn),
		Config:           NewConfigController(s.Config),
		Providers:        NewProvidersController(s.Providers),
		CompleteProfile:  NewCompleteProfileController(s.CompleteProfile),
		Me:               NewMeController(),
		Profile:          NewProfileController(s.Profile),
		MFATOTP:          NewMFATOTPController(s.MFATOTP),
		MFASMS:           NewMFASMSController(s.MFASMS),
		MFAEmail:         NewMFAEmailController(s.MFAEmail),
		MFAFactors:       NewMFAFactorController(s.MFAFactors),
		Passwordless:     NewPasswordlessController(s.Passwordless),
		Social:           social.NewControllers(s.Social),
	}
}
