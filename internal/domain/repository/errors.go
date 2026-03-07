package repository

import "errors"

var (
	// ErrNotFound indica que el recurso solicitado no existe.
	ErrNotFound = errors.New("not found")

	// ErrConflict indica un conflicto (ej: duplicado, constraint violation).
	ErrConflict = errors.New("conflict")

	// ErrInvalidInput indica que los datos de entrada son inválidos.
	ErrInvalidInput = errors.New("invalid input")

	// ErrNotImplemented indica que la operación no está implementada por este driver.
	ErrNotImplemented = errors.New("not implemented")

	// ErrNoDatabase indica que no hay base de datos configurada.
	ErrNoDatabase = errors.New("no database configured")

	// ErrUnauthorized indica que la operación no está autorizada.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrTokenExpired indica que el token ya expiró.
	ErrTokenExpired = errors.New("token expired")

	// ErrNotLeader indica que la operación requiere ser líder del cluster.
	ErrNotLeader = errors.New("not cluster leader")

	// ErrClusterUnavailable indica que el cluster no está disponible.
	ErrClusterUnavailable = errors.New("cluster unavailable")

	// ErrLastIdentity indica que no se puede eliminar la última identidad de un usuario.
	ErrLastIdentity = errors.New("cannot remove last identity")
)

// IsNotFound verifica si el error es ErrNotFound.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsConflict verifica si el error es ErrConflict.
func IsConflict(err error) bool {
	return errors.Is(err, ErrConflict)
}

// IsNoDatabase verifica si el error es ErrNoDatabase.
func IsNoDatabase(err error) bool {
	return errors.Is(err, ErrNoDatabase)
}
