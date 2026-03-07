package errors

import (
	"fmt"
	"net/http"
)

// AppError define la estructura estÃ¡ndar para errores de la aplicaciÃ³n v2
type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Detail     string `json:"detail,omitempty"`
	HTTPStatus int    `json:"-"` // No se serializa, usado para el header
	Err        error  `json:"-"` // Error original (causa), Ãºtil para logs, no se expone al cliente por defecto
}

// Error implementa la interfaz error
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap permite acceder al error original
func (e *AppError) Unwrap() error {
	return e.Err
}

// New crea un nuevo AppError
func New(status int, code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
	}
}

// Wrap crea un AppError envolviendo un error existente
func Wrap(err error, status int, code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
		Err:        err,
	}
}

// FromError intenta convertir un error genÃ©rico en un AppError.
// Si no es un AppError, devuelve un error interno genÃ©rico conservando el error original.
// Esto cumple el requerimiento de manejar errores de otras capas.
func FromError(err error) *AppError {
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}
	return ErrInternalServerError.WithCause(err)
}

// WithDetail agrega detalles adicionales al error (Ãºtil para validaciones)
// Devuelve una COPIA del error para no mutar las variables globales base
func (e *AppError) WithDetail(detail string) *AppError {
	newErr := *e
	newErr.Detail = detail
	return &newErr
}

// WithCause agrega el error original (causa)
// Devuelve una COPIA del error
func (e *AppError) WithCause(err error) *AppError {
	newErr := *e
	newErr.Err = err
	return &newErr
}

// =================================================================================
// LISTA DE ERRORES PREDEFINIDOS
// =================================================================================

// ---------------------------------------------------------------------------------
// 400 Bad Request - Errores de Cliente / ValidaciÃ³n
// ---------------------------------------------------------------------------------

var (
	ErrBadRequest = &AppError{
		Code:       "BAD_REQUEST",
		Message:    "The request has invalid syntax or missing parameters.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrInvalidJSON = &AppError{
		Code:       "INVALID_JSON",
		Message:    "The request body is not valid JSON.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrMissingFields = &AppError{
		Code:       "MISSING_FIELDS",
		Message:    "Required fields are missing in the request.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrInvalidFormat = &AppError{
		Code:       "INVALID_FORMAT",
		Message:    "One or more fields have an invalid format.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrInvalidParameter = &AppError{
		Code:       "INVALID_PARAMETER",
		Message:    "One of the URL or query string parameters is invalid.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrBodyTooLarge = &AppError{
		Code:       "BODY_TOO_LARGE",
		Message:    "The request body exceeds the maximum allowed size.",
		HTTPStatus: http.StatusRequestEntityTooLarge,
	}

	ErrGrantNotAllowed = &AppError{
		Code:       "GRANT_NOT_ALLOWED",
		Message:    "This app is not authorized for this auth method.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrClientNotFound = &AppError{
		Code:       "CLIENT_NOT_FOUND",
		Message:    "Application not found. Check your client_id.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrRedirectMismatch = &AppError{
		Code:       "REDIRECT_URI_MISMATCH",
		Message:    "Redirect URI doesn't match registered URIs.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrPKCERequired = &AppError{
		Code:       "PKCE_REQUIRED",
		Message:    "Code challenge (PKCE) is required.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrPKCEInvalid = &AppError{
		Code:       "PKCE_INVALID",
		Message:    "Code verifier doesn't match the code challenge.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrScopeNotAllowed = &AppError{
		Code:       "SCOPE_NOT_ALLOWED",
		Message:    "Requested scope(s) not authorized for this app.",
		HTTPStatus: http.StatusBadRequest,
	}
)

// ---------------------------------------------------------------------------------
// 401 Unauthorized - Errores de AutenticaciÃ³n
// ---------------------------------------------------------------------------------

var (
	ErrUnauthorized = &AppError{
		Code:       "UNAUTHORIZED",
		Message:    "Unauthorized. Authentication is required.",
		HTTPStatus: http.StatusUnauthorized,
	}

	ErrInvalidCredentials = &AppError{
		Code:       "INVALID_CREDENTIALS",
		Message:    "The email or password is incorrect.",
		HTTPStatus: http.StatusUnauthorized,
	}

	ErrTokenExpired = &AppError{
		Code:       "TOKEN_EXPIRED",
		Message:    "The access token has expired.",
		HTTPStatus: http.StatusUnauthorized,
	}

	ErrTokenInvalid = &AppError{
		Code:       "TOKEN_INVALID",
		Message:    "The access token is invalid or malformed.",
		HTTPStatus: http.StatusUnauthorized,
	}

	ErrTokenMissing = &AppError{
		Code:       "TOKEN_MISSING",
		Message:    "No authentication token was provided.",
		HTTPStatus: http.StatusUnauthorized,
	}

	ErrSessionExpired = &AppError{
		Code:       "SESSION_EXPIRED",
		Message:    "Your session has expired. Please log in again.",
		HTTPStatus: http.StatusUnauthorized,
	}

	ErrSessionNotFound = &AppError{
		Code:       "SESSION_NOT_FOUND",
		Message:    "Session not found or already logged out.",
		HTTPStatus: http.StatusUnauthorized,
	}

	ErrRefreshTokenReuse = &AppError{
		Code:       "REFRESH_TOKEN_REUSE",
		Message:    "Invalid or expired token. Please log in again.",
		HTTPStatus: http.StatusUnauthorized,
	}
)

// ---------------------------------------------------------------------------------
// 403 Forbidden - Errores de Permisos
// ---------------------------------------------------------------------------------

var (
	ErrForbidden = &AppError{
		Code:       "FORBIDDEN",
		Message:    "You do not have permission to perform this action.",
		HTTPStatus: http.StatusForbidden,
	}

	ErrAccountDisabled = &AppError{
		Code:       "ACCOUNT_DISABLED",
		Message:    "This account has been disabled. Contact support.",
		HTTPStatus: http.StatusForbidden,
	}

	ErrAccountSuspended = &AppError{
		Code:       "ACCOUNT_SUSPENDED",
		Message:    "The account is suspended and cannot perform actions.",
		HTTPStatus: http.StatusForbidden,
	}

	ErrAccountNotVerified = &AppError{
		Code:       "ACCOUNT_NOT_VERIFIED",
		Message:    "The account must be verified before continuing.",
		HTTPStatus: http.StatusForbidden,
	}

	ErrEmailNotVerified = &AppError{
		Code:       "EMAIL_NOT_VERIFIED",
		Message:    "Please verify your email before logging in.",
		HTTPStatus: http.StatusForbidden,
	}

	ErrInsufficientScopes = &AppError{
		Code:       "INSUFFICIENT_SCOPES",
		Message:    "The token does not have the required scopes for this resource.",
		HTTPStatus: http.StatusForbidden,
	}

	ErrCSRFTokenMissing = &AppError{
		Code:       "CSRF_TOKEN_MISSING",
		Message:    "Security token missing. Refresh the page.",
		HTTPStatus: http.StatusForbidden,
	}

	ErrCSRFTokenInvalid = &AppError{
		Code:       "CSRF_TOKEN_INVALID",
		Message:    "Security token mismatch. Refresh the page.",
		HTTPStatus: http.StatusForbidden,
	}
)

// ---------------------------------------------------------------------------------
// 404 Not Found - Recursos no encontrados
// ---------------------------------------------------------------------------------

var (
	ErrNotFound = &AppError{
		Code:       "NOT_FOUND",
		Message:    "The requested resource was not found.",
		HTTPStatus: http.StatusNotFound,
	}

	ErrUserNotFound = &AppError{
		Code:       "USER_NOT_FOUND",
		Message:    "The specified user does not exist.",
		HTTPStatus: http.StatusNotFound,
	}

	ErrTenantNotFound = &AppError{
		Code:       "TENANT_NOT_FOUND",
		Message:    "Organization not found. Check your tenant identifier.",
		HTTPStatus: http.StatusNotFound,
	}

	ErrRouteNotFound = &AppError{
		Code:       "ROUTE_NOT_FOUND",
		Message:    "The requested route does not exist.",
		HTTPStatus: http.StatusNotFound,
	}
)

// ---------------------------------------------------------------------------------
// 405 Method Not Allowed
// ---------------------------------------------------------------------------------

var (
	ErrMethodNotAllowed = &AppError{
		Code:       "METHOD_NOT_ALLOWED",
		Message:    "The HTTP method is not allowed for this resource.",
		HTTPStatus: http.StatusMethodNotAllowed,
	}
)

// ---------------------------------------------------------------------------------
// 409 Conflict - Errores de Estado/Conflicto
// ---------------------------------------------------------------------------------

var (
	ErrConflict = &AppError{
		Code:       "CONFLICT",
		Message:    "The request conflicts with the current server state.",
		HTTPStatus: http.StatusConflict,
	}

	ErrAlreadyExists = &AppError{
		Code:       "ALREADY_EXISTS",
		Message:    "The resource already exists.",
		HTTPStatus: http.StatusConflict,
	}

	ErrEmailAlreadyInUse = &AppError{
		Code:       "EMAIL_ALREADY_IN_USE",
		Message:    "The email address is already registered.",
		HTTPStatus: http.StatusConflict,
	}

	ErrUsernameTaken = &AppError{
		Code:       "USERNAME_TAKEN",
		Message:    "The username is already in use.",
		HTTPStatus: http.StatusConflict,
	}
)

// ---------------------------------------------------------------------------------
// 410 Gone
// ---------------------------------------------------------------------------------

var (
	ErrGone = &AppError{
		Code:       "GONE",
		Message:    "The requested resource is no longer available.",
		HTTPStatus: http.StatusGone,
	}
)

// ---------------------------------------------------------------------------------
// 422 Unprocessable Entity - Errores de LÃ³gica de Negocio
// ---------------------------------------------------------------------------------

var (
	ErrUnprocessableEntity = &AppError{
		Code:       "UNPROCESSABLE_ENTITY",
		Message:    "The instructions in the request could not be processed.",
		HTTPStatus: http.StatusUnprocessableEntity,
	}

	ErrPasswordTooWeak = &AppError{
		Code:       "PASSWORD_TOO_WEAK",
		Message:    "The password does not meet security requirements.",
		HTTPStatus: http.StatusUnprocessableEntity,
	}

	// ─── Bot Protection ───────────────────────────────────────────────────────────

	// ErrBotTokenMissing se retorna cuando bot protection está habilitado
	// pero el request no incluye el token de verificación.
	ErrBotTokenMissing = &AppError{
		Code:       "BOT_TOKEN_MISSING",
		Message:    "Bot verification token is required. Please reload the page and try again.",
		HTTPStatus: http.StatusUnprocessableEntity,
	}

	// ErrBotVerificationFailed se retorna cuando el token de bot protection no es válido.
	ErrBotVerificationFailed = &AppError{
		Code:       "BOT_VERIFICATION_FAILED",
		Message:    "Bot verification failed. Please try again.",
		HTTPStatus: http.StatusUnprocessableEntity,
	}
)

// ---------------------------------------------------------------------------------
// 424 Failed Dependency - Dependencia no configurada
// ---------------------------------------------------------------------------------

var (
	ErrTenantNoDatabase = &AppError{
		Code:       "TENANT_NO_DATABASE",
		Message:    "This organization hasn't configured a database yet.",
		HTTPStatus: http.StatusServiceUnavailable,
	}
)

// ---------------------------------------------------------------------------------
// 412 Precondition Failed & 428 Precondition Required - Concurrency Control
// ---------------------------------------------------------------------------------

var (
	ErrPreconditionFailed = &AppError{
		Code:       "PRECONDITION_FAILED",
		Message:    "The request precondition failed (e.g., ETag mismatch).",
		HTTPStatus: http.StatusPreconditionFailed,
	}

	ErrPreconditionRequired = &AppError{
		Code:       "PRECONDITION_REQUIRED",
		Message:    "A precondition is required (e.g., If-Match).",
		HTTPStatus: http.StatusPreconditionRequired,
	}
)

// ---------------------------------------------------------------------------------
// 429 Too Many Requests - Rate Limiting
// ---------------------------------------------------------------------------------

var (
	ErrRateLimitExceeded = &AppError{
		Code:       "RATE_LIMIT_EXCEEDED",
		Message:    "Too many requests. Please wait.",
		HTTPStatus: http.StatusTooManyRequests,
	}
)

// ---------------------------------------------------------------------------------
// 500+ Server Errors - Errores Internos
// ---------------------------------------------------------------------------------

var (
	ErrInternalServerError = &AppError{
		Code:       "INTERNAL_SERVER_ERROR",
		Message:    "An internal server error occurred.",
		HTTPStatus: http.StatusInternalServerError,
	}

	ErrNotImplemented = &AppError{
		Code:       "NOT_IMPLEMENTED",
		Message:    "This functionality is not implemented yet.",
		HTTPStatus: http.StatusNotImplemented,
	}

	ErrServiceUnavailable = &AppError{
		Code:       "SERVICE_UNAVAILABLE",
		Message:    "The service is temporarily unavailable.",
		HTTPStatus: http.StatusServiceUnavailable,
	}

	ErrGatewayTimeout = &AppError{
		Code:       "GATEWAY_TIMEOUT",
		Message:    "The server took too long to respond.",
		HTTPStatus: http.StatusGatewayTimeout,
	}

	ErrBadGateway = &AppError{
		Code:       "BAD_GATEWAY",
		Message:    "Could not establish a connection to the upstream service.",
		HTTPStatus: http.StatusBadGateway,
	}

	ErrConnectionFailed = &AppError{
		Code:       "CONNECTION_FAILED",
		Message:    "The connection to the target server was refused.",
		HTTPStatus: http.StatusBadGateway,
	}
)
