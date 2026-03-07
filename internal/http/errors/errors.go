package errors

import (
	"encoding/json"
	"net/http"
)

// errorResponse structura interna para la serialización JSON.
// Esto nos permite controlar exactamente qué campos se envían al cliente.
type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// WriteError escribe una respuesta HTTP basada en el error proporcionado.
// Maneja automáticamente errores de tipo *AppError y errores genéricos.
func WriteError(w http.ResponseWriter, err error) {
	// Asegurarnos de que estamos tratando con un AppError
	appErr := FromError(err)

	// Preparar la respuesta JSON
	resp := errorResponse{
		Code:    appErr.Code,
		Message: appErr.Message,
		Detail:  appErr.Detail,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(appErr.HTTPStatus)

	// En un caso real, aquí podríamos loguear el error original (appErr.Err)
	// si el status es 500 o si es un error crítico.

	_ = json.NewEncoder(w).Encode(resp)
}
