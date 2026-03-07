package middlewares

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// WithTenantFromJSONBody lee el body (hasta 32KB) para extraer tenant_id o tenant
// y lo inyecta en el header X-Tenant-ID si no se resolvió por otros medios.
// Realiza un "peek" seguro sin truncar el body original.
func WithTenantFromJSONBody() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Si ya hay tenant por header/query/subdomain, no tocamos nada.
			if r.Header.Get("X-Tenant-ID") != "" || r.Header.Get("X-Tenant-Slug") != "" {
				next.ServeHTTP(w, r)
				return
			}
			if r.URL.Query().Get("tenant") != "" || r.URL.Query().Get("tenant_id") != "" {
				next.ServeHTTP(w, r)
				return
			}

			// Solo nos interesa POST/PUT/PATCH con Content-Type json
			if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
				next.ServeHTTP(w, r)
				return
			}
			ct := r.Header.Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				next.ServeHTTP(w, r)
				return
			}

			// Leer body limitado (32KB + 1 byte para detectar si es mayor)
			const limit = 32 << 10
			b, err := io.ReadAll(io.LimitReader(r.Body, int64(limit+1)))
			if err != nil {
				// Si falla leer, intentamos restaurar y seguir
				r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
				next.ServeHTTP(w, r)
				return
			}
			// Restaurar body COMPLETO para el siguiente handler
			// (lo que leímos + lo que falta en r.Body)
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))

			if len(b) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Si el body es mayor a 32KB (leímos 32KB+1), no parseamos para evitar overhead
			if len(b) > limit {
				next.ServeHTTP(w, r)
				return
			}

			// Parsear JSON básico
			var m map[string]any
			if json.Unmarshal(b, &m) != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Buscar tenant_id o tenant
			if v, ok := m["tenant_id"].(string); ok {
				v = strings.TrimSpace(v)
				if v != "" {
					r.Header.Set("X-Tenant-ID", v)
				}
			} else if v, ok := m["tenant"].(string); ok {
				v = strings.TrimSpace(v)
				if v != "" {
					// "tenant" suele ser el slug
					r.Header.Set("X-Tenant-Slug", v)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
