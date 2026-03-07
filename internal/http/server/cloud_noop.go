//go:build !cloud

package server

import "net/http"

// registerCloudExtensions es un no-op en el build OSS.
// En el build cloud, wiring_cloud.go (con //go:build cloud) provee la implementación real.
func registerCloudExtensions(mux *http.ServeMux, deps cloudDeps) {
	_ = mux
	_ = deps
}
