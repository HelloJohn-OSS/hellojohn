package middlewares

import (
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/http/errors"
)

// =================================================================================
// CLUSTER MIDDLEWARE
// =================================================================================

// RequireLeader asegura que las operaciones de escritura solo se ejecuten en el nodo líder.
// Comportamiento:
//   - Si no hay cluster o el nodo es líder => pasa.
//   - Si es follower => devuelve 409 Conflict con X-Leader header.
//   - Si el cliente solicita redirect (X-Leader-Redirect: 1 o query leader_redirect=1)
//     y hay una URL de líder configurada => responde 307.
func RequireLeader(clusterRepo repository.ClusterRepository, leaderRedirects map[string]string) Middleware {
	// Construir allowlist de hosts para redirects (seguridad)
	allowlist := make(map[string]struct{})
	for _, url := range leaderRedirects {
		if host := extractHost(url); host != "" {
			allowlist[strings.ToLower(host)] = struct{}{}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Solo aplica a métodos de escritura
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				// continuar
			default:
				next.ServeHTTP(w, r)
				return
			}

			// Si no hay cluster o somos líder, permitir
			if clusterRepo == nil {
				next.ServeHTTP(w, r)
				return
			}

			isLeader, err := clusterRepo.IsLeader(r.Context())
			if err != nil || isLeader {
				next.ServeHTTP(w, r)
				return
			}

			// Somos follower
			leaderID, _ := clusterRepo.GetLeaderID(r.Context())
			if leaderID != "" {
				w.Header().Set("X-Leader", leaderID)
			}

			// ¿Pidió redirect explícito el cliente?
			wantsRedirect := strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Leader-Redirect")), "1") ||
				strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("leader_redirect")), "1")

			if wantsRedirect && leaderID != "" && leaderRedirects != nil {
				if base, ok := leaderRedirects[leaderID]; ok && strings.TrimSpace(base) != "" {
					ub := strings.TrimSpace(base)
					low := strings.ToLower(ub)
					if (strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")) && !strings.Contains(ub, " ") {
						// Validar host está en allowlist
						host := extractHost(ub)
						if _, ok := allowlist[strings.ToLower(host)]; ok {
							ub = strings.TrimRight(ub, "/")
							loc := ub + r.URL.RequestURI()
							w.Header().Set("X-Leader-URL", ub)
							w.Header().Set("Location", loc)
							w.WriteHeader(http.StatusTemporaryRedirect)
							return
						}
					}
				}
			}

			// Fallback: 409 con error estándar
			errors.WriteError(w, errors.ErrConflict.WithDetail("this node is a follower, not the leader"))
		})
	}
}

// extractHost extrae el host:port de una URL.
func extractHost(url string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		url = url[i+3:]
	}
	if j := strings.Index(url, "/"); j >= 0 {
		url = url[:j]
	}
	return url
}
