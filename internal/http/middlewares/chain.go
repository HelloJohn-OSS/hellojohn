package middlewares

import "net/http"

// Middleware es un decorador de http.Handler
type Middleware func(http.Handler) http.Handler

// Chain aplica middlewares en orden de izquierda a derecha.
// Chain(h, A, B, C) ejecuta: A -> B -> C -> h
// Es decir, A es el primero en interceptar el request y el último en ver la respuesta.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	// Aplicamos en orden inverso para que el primero en la lista sea el más externo
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// ChainFunc es un helper para encadenar middlewares a un http.HandlerFunc
func ChainFunc(hf http.HandlerFunc, mws ...Middleware) http.Handler {
	return Chain(hf, mws...)
}
