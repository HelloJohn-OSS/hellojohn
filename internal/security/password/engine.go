package password

// PolicyContext contiene metadata contextual para reglas que necesitan
// información del usuario (ej. PersonalInfoRule, HistoryRule).
type PolicyContext struct {
	UserID     string
	Email      string
	Name       string
	PrevHashes []string // histórico de hashes para HistoryRule
}

// Violation describe por qué falló una regla de política de contraseñas.
type Violation struct {
	Rule    string         `json:"rule"`
	Message string         `json:"message"`
	Params  map[string]any `json:"params,omitempty"`
}

// PolicyRule evalúa una regla individual de política de contraseñas.
// Cada implementación concreta retorna nil si la contraseña cumple la regla,
// o un *Violation describiendo por qué no la cumple.
type PolicyRule interface {
	Name() string
	Validate(password string, ctx PolicyContext) *Violation
}

// PolicyEngine encadena múltiples reglas según la configuración del tenant.
// Evalúa secuencialmente cada regla y acumula todas las violaciones.
type PolicyEngine struct {
	rules []PolicyRule
}

// NewPolicyEngine crea un engine con las reglas proporcionadas.
func NewPolicyEngine(rules ...PolicyRule) *PolicyEngine {
	return &PolicyEngine{rules: rules}
}

// Validate ejecuta todas las reglas contra la contraseña y retorna
// todas las violaciones encontradas. Retorna nil/empty si la contraseña
// cumple todas las reglas.
func (e *PolicyEngine) Validate(password string, ctx PolicyContext) []Violation {
	var violations []Violation
	for _, rule := range e.rules {
		if v := rule.Validate(password, ctx); v != nil {
			violations = append(violations, *v)
		}
	}
	return violations
}
