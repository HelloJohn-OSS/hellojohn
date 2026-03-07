package helpers

import "strings"

// ─────────────────────────────────────────────────────────────────────────────
// PROVIDERS HELPERS
// ─────────────────────────────────────────────────────────────────────────────

// IsProviderAllowed verifica si un provider específico está permitido.
// Si la lista de providers está vacía, todos están permitidos.
// La comparación es case-insensitive.
func IsProviderAllowed(providers []string, provider string) bool {
	if len(providers) == 0 {
		return true // Sin restricción
	}
	for _, p := range providers {
		if strings.EqualFold(p, provider) {
			return true
		}
	}
	return false
}

// IsPasswordProviderAllowed es un helper específico para verificar si
// el provider "password" está permitido para un client.
func IsPasswordProviderAllowed(providers []string) bool {
	return IsProviderAllowed(providers, "password")
}

// IsGoogleProviderAllowed verifica si Google login está permitido.
func IsGoogleProviderAllowed(providers []string) bool {
	return IsProviderAllowed(providers, "google")
}
