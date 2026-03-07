// Package controllers agrupa todos los controllers HTTP V2.
// Este es el "composition root" de controllers.
//
//  1. CREAR EL SUB-PAQUETE:
//     internal/http/v2/controllers/{dominio}/
//     - {nombre}_controller.go  → implementación del controller
//     - controllers.go          → aggregator del dominio
//
// 2. DEFINIR EL AGGREGATOR DEL DOMINIO (controllers/{dominio}/controllers.go):
//
//	import svc "github.com/.../services/{dominio}"
//
//	type Controllers struct {
//	    MiController *MiController
//	}
//
//	func NewControllers(s svc.Services) *Controllers {
//	    return &Controllers{
//	        MiController: NewMiController(s.MiService),
//	    }
//	}
//
// 3. AGREGAR AL AGGREGATOR PRINCIPAL (este archivo):
//   - Importar el paquete del dominio
//   - Agregar campo al struct Controllers
//   - Inicializar en el constructor New()
//
// 4. USO EN app.go o main.go:
//
//	// Primero crear services (ver services/services.go)
//	svcs := services.New(deps)
//
//	// Luego crear controllers inyectando services
//	ctrls := controllers.New(svcs)
//
//	// Finalmente registrar rutas inyectando controllers
//	router.RegisterAdminRoutes(mux, router.AdminRouterDeps{
//	    DAL:         dal,
//	    Issuer:      issuer,
//	    Controllers: ctrls.Admin,
//	})
//	router.RegisterAuthRoutes(mux, router.AuthRouterDeps{
//	    Controllers: ctrls.Auth,
//	    RateLimiter: rateLimiter,  // opcional
//	})
//	router.RegisterOIDCRoutes(mux, router.OIDCRouterDeps{
//	    Controllers: ctrls.OIDC,
//	    Issuer:      issuer,
//	})
//	router.RegisterHealthRoutes(mux, router.HealthRouterDeps{
//	    Controllers: ctrls.Health,
//	})
//
// ═══════════════════════════════════════════════════════════════════════════════
// FLUJO DE INICIALIZACIÓN (cascada de dependencias)
// ═══════════════════════════════════════════════════════════════════════════════
//
//	┌───────────────────────────────────────────────────────────────────────────┐
//	│  app.go / main.go                                                         │
//	│                                                                           │
//	│  1. deps := services.Deps{...}      ← Inyectar dependencias externas     │
//	│           ▼                                                               │
//	│  2. svcs := services.New(deps)      ← Crear todos los services           │
//	│           ▼                                                               │
//	│  3. ctrls := controllers.New(svcs)  ← Crear controllers con services     │
//	│           ▼                                                               │
//	│  4. router.Register*(mux, deps)     ← Registrar rutas con controllers    │
//	│           ▼                                                               │
//	│  5. http.ListenAndServe(addr, mux)  ← Iniciar servidor                   │
//	└───────────────────────────────────────────────────────────────────────────┘
//
// ═══════════════════════════════════════════════════════════════════════════════
package controllers

import (
	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/http/controllers/admin"
	"github.com/dropDatabas3/hellojohn/internal/http/controllers/auth"
	cloudctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/cloud"
	"github.com/dropDatabas3/hellojohn/internal/http/controllers/health"
	"github.com/dropDatabas3/hellojohn/internal/http/controllers/oidc"
	"github.com/dropDatabas3/hellojohn/internal/http/controllers/social"
	sessiondto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	"github.com/dropDatabas3/hellojohn/internal/http/services"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Controllers agrupa todos los sub-controllers por dominio.
// Cada dominio tiene su propio aggregator en su sub-paquete.
type Controllers struct {
	Admin  *admin.Controllers     // Operaciones admin (clients, users, scopes, rbac, consents)
	Auth   *auth.Controllers      // Autenticación (login, refresh, register)
	OIDC   *oidc.Controllers      // OIDC (jwks, discovery, userinfo)
	Health *health.Controllers    // Health checks (readyz)
	Social *social.Controllers    // Social login (start, callback, exchange)
	Cloud  *cloudctrl.Controllers // Cloud Control Plane (nil si no configurado)
}

// Deps contiene dependencias adicionales para controllers que no vienen de services.
type Deps struct {
	DAL          store.DataAccessLayer
	LogoutConfig sessiondto.SessionLogoutConfig
	SessionCache cache.Client
}

// New crea el agregador de controllers con todos los services inyectados.
// Este es el único lugar donde se instancian los controllers.
//
// Los services ya deben estar creados via services.New(deps).
func New(svc *services.Services, deps Deps) *Controllers {
	return &Controllers{
		Admin: admin.NewControllers(svc.Admin, admin.ControllerDeps{
			DAL:          deps.DAL,
			ControlPlane: svc.Admin.ControlPlane, // Accesible desde Admin Services
		}),
		Auth: auth.NewControllers(svc.Auth, auth.ControllerDeps{
			LogoutConfig: deps.LogoutConfig,
			DAL:          deps.DAL,
			SessionCache: deps.SessionCache,
		}),
		OIDC:   oidc.NewControllers(svc.OIDC),
		Health: health.NewControllers(svc.Health),
		Social: social.NewControllers(svc.Social),
	}
}
