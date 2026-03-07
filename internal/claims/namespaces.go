package claims

import "strings"

const devSysNSFallback = "https://hellojohn.local/claims/sys"

// SystemNamespace construye el namespace de claims "de sistema" anclado al issuer.
// Ej: https://issuer.example/claims/sys
func SystemNamespace(issuer string) string {
	iss := strings.TrimSpace(issuer)
	if iss == "" {
		return devSysNSFallback // sólo dev
	}
	return strings.TrimRight(iss, "/") + "/claims/sys"
}

// EnforceNamespace asegura que los claims personalizados cumplan con el estándar OIDC.
// Para evitar colisiones en el diccionario raíz (root claims) con firmas IANA reservadas (sub, iss, exp),
// todo custom claim que no declare ya un sufijo de internet (ej URI o URN) es prefijado.
func EnforceNamespace(key string) string {
	// Si el string ya tiene el patrón de protocolo/URI (ej https://, auth://, urn:)
	if strings.Contains(key, "://") || strings.HasPrefix(key, "urn:") || strings.HasPrefix(key, "http") {
		return key
	}
	// Si no, forzamos Namespace propio.
	return "https://hellojohn.dev/claims/" + key
}
