package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// ETag calcula un ETag estable a partir de bytes.
// Devuelve un ETag fuerte con comillas, usando un hash truncado para hacerlo corto.
func ETag(data []byte) string {
	sum := sha256.Sum256(data)
	// 8 bytes = 16 hex chars (suficiente para control de concurrencia optimista)
	short := hex.EncodeToString(sum[:8])
	return `"` + short + `"`
}

// IfMatchOK valida el header If-Match contra un ETag.
// Acepta "*" como match.
func IfMatchOK(r *http.Request, etag string) bool {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if v == "" {
		return false
	}
	if v == "*" {
		return true
	}
	return v == etag
}
