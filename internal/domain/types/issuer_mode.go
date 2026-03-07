// Package types define tipos de dominio compartidos entre paquetes.
package types

// IssuerMode configura cómo se construye el issuer/JWKS por tenant.
type IssuerMode string

const (
	// IssuerModeGlobal usa el issuer base para todos los tenants (default/compat).
	IssuerModeGlobal IssuerMode = "global"
	// IssuerModePath construye issuer como {base}/t/{slug}.
	IssuerModePath IssuerMode = "path"
	// IssuerModeDomain usa subdominio por tenant (futuro).
	IssuerModeDomain IssuerMode = "domain"
)

// IsValid retorna true si el modo es válido.
func (m IssuerMode) IsValid() bool {
	switch m {
	case "", IssuerModeGlobal, IssuerModePath, IssuerModeDomain:
		return true
	}
	return false
}
