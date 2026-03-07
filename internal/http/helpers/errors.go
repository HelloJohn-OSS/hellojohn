package helpers

import (
	"encoding/json"
	"net/http"
)

// Standard Error Responses

var (
	ErrInvalidJSON         = &HTTPError{Code: "invalid_json", Message: "Invalid JSON format", Status: http.StatusBadRequest}
	ErrBadRequest          = &HTTPError{Code: "bad_request", Message: "Bad request", Status: http.StatusBadRequest}
	ErrUnauthorized        = &HTTPError{Code: "unauthorized", Message: "Unauthorized", Status: http.StatusUnauthorized}
	ErrForbidden           = &HTTPError{Code: "forbidden", Message: "Forbidden", Status: http.StatusForbidden}
	ErrNotFound            = &HTTPError{Code: "not_found", Message: "Not found", Status: http.StatusNotFound}
	ErrMethodNotAllowed    = &HTTPError{Code: "method_not_allowed", Message: "Method not allowed", Status: http.StatusMethodNotAllowed}
	ErrInternalServerError = &HTTPError{Code: "internal_error", Message: "Internal server error", Status: http.StatusInternalServerError}
	ErrServiceUnavailable  = &HTTPError{Code: "service_unavailable", Message: "Service unavailable", Status: http.StatusServiceUnavailable}
)

// HTTPError represents a standard API error.
type HTTPError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	Status  int    `json:"-"`
}

func (e *HTTPError) Error() string {
	if e.Detail != "" {
		return e.Message + ": " + e.Detail
	}
	return e.Message
}

// WithDetail returns a copy of the error with specific details.
func (e *HTTPError) WithDetail(detail string) *HTTPError {
	return &HTTPError{
		Code:    e.Code,
		Message: e.Message,
		Detail:  detail,
		Status:  e.Status,
	}
}

// WriteError writes the error to the response writer.
func WriteError(w http.ResponseWriter, err error) {
	var httpErr *HTTPError
	if hErr, ok := err.(*HTTPError); ok {
		httpErr = hErr
	} else {
		// Default to internal error if unknown type
		httpErr = ErrInternalServerError
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpErr.Status)
	_ = json.NewEncoder(w).Encode(httpErr)
}
