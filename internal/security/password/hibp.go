package password

import (
	"crypto/sha1" //nolint:gosec // SHA-1 required by HIBP k-Anonymity protocol
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BreachDetectionRule consulta la API de Have I Been Pwned (HIBP) usando
// el modelo de k-Anonymity: solo envía los primeros 5 caracteres del hash SHA-1
// de la contraseña. Si HIBP no responde dentro del timeout, la regla
// aplica "Graceful Degradation" (fail-open) y permite la contraseña.
type BreachDetectionRule struct {
	Client *http.Client
}

// NewBreachDetectionRule crea la regla con un HTTP client con timeout de 2s.
func NewBreachDetectionRule() BreachDetectionRule {
	return BreachDetectionRule{
		Client: &http.Client{Timeout: 2 * time.Second},
	}
}

func (r BreachDetectionRule) Name() string { return "breach_detection" }

func (r BreachDetectionRule) Validate(password string, _ PolicyContext) *Violation {
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}

	// SHA-1 hash de la contraseña (requerido por el protocolo HIBP)
	hash := sha1.Sum([]byte(password)) //nolint:gosec
	hashStr := strings.ToUpper(fmt.Sprintf("%x", hash))

	prefix := hashStr[:5]
	suffix := hashStr[5:]

	resp, err := client.Get("https://api.pwnedpasswords.com/range/" + prefix)
	if err != nil {
		// Fail-open: si HIBP está caído, no bloquear al usuario
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil // Fail-open ante respuestas inesperadas
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) > 0 && parts[0] == suffix {
			return &Violation{
				Rule:    r.Name(),
				Message: "This password has appeared in a data breach. Please choose a different one.",
			}
		}
	}

	return nil
}
