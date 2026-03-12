//go:build cloud

package server

import "net/http"

// registerCloudExtensions is intentionally a no-op in OSS even when built with -tags cloud.
// This keeps OSS buildable in CI scripts that pass cloud tags while not enabling cloud routes.
func registerCloudExtensions(mux *http.ServeMux, deps cloudDeps) {
	_ = mux
	_ = deps
}
