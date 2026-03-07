package claims

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/google/cel-go/cel"
)

// ValidateClaimConfig evalúa que la configuración ingresada por un Administrador sea
// estructuralmente y léxicamente válida dadas las exigencias del motor asociado (CEL o Webhooks).
// Evita que los tenants configuren expresiones rotas que crashearían la gorutine durante Login auth.
func ValidateClaimConfig(resolverType string, configData map[string]any) error {
	switch resolverType {

	case "expression":
		if configData == nil {
			return errors.New("resolver 'expression' exige la llave 'expression' en su config data")
		}
		exprObj, ok := configData["expression"]
		if !ok {
			return errors.New("resolver 'expression' requiere estrictamente el campo 'expression' (string)")
		}
		exprBody, ok := exprObj.(string)
		if !ok || exprBody == "" {
			return errors.New("el campo 'expression' no debe estar vacío y debe ser de tipo string")
		}
		return validateCelSyntax(exprBody)

	case "webhook_api":
		if configData == nil {
			return errors.New("resolver 'webhook_api' requiere 'url' y opcionalmente 'headers'")
		}
		urlObj, ok := configData["url"]
		if !ok {
			return errors.New("resolver 'webhook_api' requiere estrictamente el campo 'url'")
		}
		urlBody, ok := urlObj.(string)
		if !ok || urlBody == "" {
			return errors.New("el campo 'url' debe ser string no vacío")
		}
		return validateWebhookURL(urlBody)

	case "user_attribute":
		if configData == nil {
			return errors.New("resolver 'user_attribute' requiere el campo 'field'")
		}
		_, ok := configData["field"]
		if !ok {
			return errors.New("resolver 'user_attribute' falta declarar 'field'")
		}
		return nil

	case "rbac":
		// rbac is boolean toggles
		return nil

	case "static":
		return nil

	default:
		// Evitar injecciones al enumerador del Orquestador OIDC.
		return fmt.Errorf("tipo de resolver '%s' es completamente inválido y no está soportado", resolverType)
	}
}

func validateCelSyntax(expression string) error {
	// Declaramos un Sandbox CEL temporal con las variables idénticas a ResolverInput
	// exclusivamente para que compile (checkear AST). No lo evaluamos realmente en tiempo de petición (eso en Login)
	env, err := cel.NewEnv(
		cel.Variable("input", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return fmt.Errorf("error interno al instanciar sandbox CEL syntax checker: %w", err)
	}

	ast, iss := env.Compile(expression)
	if iss.Err() != nil {
		return fmt.Errorf("sintaxis CEL incorrecta o variables no declaradas:\n%w", iss.Err())
	}

	// Comprobamos la inferencia que obliga a los ExpresionResolver a retornar
	// Strings, Ints, Bools, pero nunca Nulls directos ni funciones abstractas
	if ast.OutputType().IsExactType(cel.NullType) {
		return errors.New("la evaluación no puede dar garantizado un tipo Null perpetuo. Requiere derivar un string, map o boolean")
	}

	return nil
}

func validateWebhookURL(targetUrl string) error {
	u, err := url.ParseRequestURI(targetUrl)
	if err != nil {
		return fmt.Errorf("URL del webhook malformada: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("webhook exige un esquema protocolar http o https")
	}

	// En E005 el Hardened Client rechaza 10.x.x, 192.168.x y Localhost.
	// Haremos una pre-alerta básica amigable.
	h := u.Hostname()
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return errors.New("webhooks no pueden apuntar al loopback localhost en el ámbito de Claims (Prohibido por Hardened SSRF policy)")
	}

	return nil
}
