// Package security contains controllers for security-related endpoints.
package security

import svc "github.com/dropDatabas3/hellojohn/internal/http/services/security"

// Controllers agrupa todos los controllers del dominio security.
type Controllers struct {
	CSRF *CSRFController
}

// NewControllers creates the security controllers aggregator.
func NewControllers(s svc.Services) *Controllers {
	return &Controllers{
		CSRF: NewCSRFController(s.CSRF),
	}
}
