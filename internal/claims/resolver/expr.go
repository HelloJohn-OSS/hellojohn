package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
)

// ExpressionResolver implementa la Interfaz Resolver y ejecuta operaciones
// lógicas y matemáticas en un AST Compilado (CEL Program) para devolver Claims Custom.
// Utiliza un mecanismo estricto de Timeboxing para resguardar el Request-Time de Login.
type ExpressionResolver struct {
	program cel.Program // Programa AST pre-compilado en el Arranque (Load-Time)
}

// NewExpressionResolver es un constructor seguro que inyecta el programa en
// duro instanciado previamente en la capa de Configuración por el admin.
func NewExpressionResolver(prg cel.Program) *ExpressionResolver {
	return &ExpressionResolver{
		program: prg,
	}
}

// Name devuelve el identificador formal "expression".
func (e *ExpressionResolver) Name() string {
	return "expression"
}

// Resolve toma el programa AST y lo evalúa contra el Payload Map transitivo "input".
// PROTECCIÓN ESTRICTA: El tiempo de contexto local está sellado a 50 milisegundos.
func (e *ExpressionResolver) Resolve(ctx context.Context, input ResolverInput) (any, error) {
	// TIMEBOXING EN REQUEST-TIME (Protección de DoS de CPU por Expresiones complejas)
	evalCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	// Convertir un Go Struct Fuerte a la Primitiva genérica que consumirá Google CEL.
	// Esto genera la variable inyectada "input" para que el usuario escriba: `input.Email == "..."`
	inputMap := map[string]any{
		"UserID":      input.UserID,
		"TenantID":    input.TenantID,
		"Email":       input.Email,
		"Scopes":      input.Scopes,
		"ClientID":    input.ClientID,
		"Roles":       input.Roles,
		"Permissions": input.Permissions,
		// UserMeta puede ser gigantesco, se inyecta como primitive dict.
		"UserMeta": input.UserMeta,
	}

	// Variables enviadas condicionalmente a la evaluación de memoria aislada de Sandbox.
	vars := map[string]any{
		"input": inputMap,
	}

	// Evaluación de Expresiones.
	// CEL-Go no es 100% dependiente de context Cancel en ops de microsegundo.
	// Hacemos un check defensivo preliminar para ver si el contexto padre ya estaba quemado.
	if err := evalCtx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			return nil, fmt.Errorf("CEL evaluation timed out (50ms strict limit reached). Defensive abort")
		}
		return nil, fmt.Errorf("CEL execution aborted by canceled context: %w", err)
	}

	val, _, err := e.program.ContextEval(evalCtx, vars)
	if err != nil {
		// Detectamos si el error viene por el vencimiento del Deadline fijado a 50ms
		if evalCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("CEL evaluation timed out (50ms strict limit reached). Defensive abort")
		}
		return nil, fmt.Errorf("CEL evaluation failed natively: %w", err)
	}

	return val.Value(), nil
}
