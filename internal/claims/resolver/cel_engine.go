package resolver

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
)

// CELEngine encapsula el entorno de evaluación de Google CEL para custom claims.
// Actúa como un *Compile-Time Sandbox*. Todas las reglas definidas por el Tenant
// DEBEN compilarse (AST) a través de esta instancia antes de persistirse.
type CELEngine struct {
	env *cel.Env
}

// NewCELEngine inicializa el compilador inyectando el contrato base obligatorio.
// Explicita al engine que quien escriba la regla tendrá a su disposición una
// estructura raíz llamada `input` (que equivale al struct ResolverInput).
func NewCELEngine() (*CELEngine, error) {
	// Declaramos estáticamente las variables e interfaces que el lenguaje
	// CEL de Google admitirá durante la escritura de una Expresión Matemática/Lógica.
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("input", decls.NewMapType(decls.String, decls.Any)),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init CEL engine: %w", err)
	}

	return &CELEngine{env: env}, nil
}

// Compile realiza el Syntax Check de una expresión de texto enviada por un
// administrador de cuenta y genera el Ast Abstracto (Executable Program).
// ESTE METODO ES COSTOSO Y DEBE EJECUTARSE SOLO EN FASE DE ARRANQUE/GUARDADO (Load-Time).
func (c *CELEngine) Compile(expression string) (cel.Program, error) {
	// 1. Parsear texto a Arbol de Sintaxis
	ast, issues := c.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL syntax error: %w", issues.Err())
	}

	// 2. Generar un programa inmutable thread-safe (Ejecutable concurrente)
	prg, err := c.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program generation error: %w", err)
	}

	return prg, nil
}
