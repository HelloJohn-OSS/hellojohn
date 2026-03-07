package helpers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// ReadJSON decodifica JSON de forma tolerante (no falla por campos desconocidos).
// Valida Content-Type y limita el body a 1MB.
// Devuelve false si ya escribió error HTTP.
func ReadJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.Contains(ct, "application/json") {
		http.Error(w, "Content-Type debe ser application/json", http.StatusBadRequest)
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil && err != io.EOF {
		http.Error(w, "json inválido", http.StatusBadRequest)
		return false
	}
	return true
}

// WriteJSON escribe una respuesta JSON estándar.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteErrorJSON escribe un error JSON estándar.
func WriteErrorJSON(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"error": message})
}
