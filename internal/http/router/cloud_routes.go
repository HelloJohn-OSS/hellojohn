package router

import (
	"net/http"

	cloudctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/cloud"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
)

// CloudRouterDeps is kept for compatibility in OSS builds.
type CloudRouterDeps struct {
	Controllers *cloudctrl.Controllers
	Issuer      *jwtx.Issuer
}

// RegisterCloudRoutes is a no-op in OSS builds.
func RegisterCloudRoutes(_ *http.ServeMux, _ CloudRouterDeps) {}
