// Package social contains controllers for social login endpoints.
package social

import svc "github.com/dropDatabas3/hellojohn/internal/http/services/social"

// Controllers agrupa todos los controllers del dominio social.
type Controllers struct {
	Exchange *ExchangeController
	Result   *ResultController
	Start    *StartController
	Callback *CallbackController
}

// NewControllers creates the social controllers aggregator.
func NewControllers(s svc.Services) *Controllers {
	return &Controllers{
		Exchange: NewExchangeController(s.Exchange),
		Result:   NewResultController(s.Result),
		Start:    NewStartController(s.Start),
		Callback: NewCallbackController(s.Callback, s.StateSigner),
	}
}
