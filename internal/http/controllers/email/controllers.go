// Package email contains controllers for email flow endpoints.
package email

import svc "github.com/dropDatabas3/hellojohn/internal/http/services/email"

// Controllers agrupa todos los controllers del dominio email.
type Controllers struct {
	Flows *FlowsController
}

// NewControllers creates the email controllers aggregator.
func NewControllers(s svc.Services) *Controllers {
	return &Controllers{
		Flows: NewFlowsController(s.Flows),
	}
}
