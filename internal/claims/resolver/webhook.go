package resolver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
)

// Constantes de Defensa Críticas
const (
	maxWebhookTimeout  = 2 * time.Second // Timeboxing en Requests Sincrónicos Bloqueantes
	maxWebhookBodySize = 16 * 1024       // 16 KB límite contra RAM Data Bloom attacks
)

// WebhookResolver delega la evaluación de Claims a una API Remota del Tenant
// de forma sincrónica durante el login, aportando flexibilidad sin límites.
type WebhookResolver struct {
	URL          string
	SecretEnc    string // Secret guardado en BD encriptado vía AES-GCM (SecretBox)
	Timeout      time.Duration
	Headers      map[string]string
	parsedSecret string // Se resuelve en Load-Time para evitar AES overhead per-request
}

// isSSRFVulnerable escanea una URL para evitar envíos de red maliciosos hacia Localhost,
// Redes Privadas de Nube (10.x, 169.254.x) y VPCs aislando ataques SSRF.
func isSSRFVulnerable(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true // Bloquear por mala forma
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return true // Solo esquemas web
	}

	host := parsed.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			return true // Fallo DNS, bloquear dudables
		}
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
	}
	return false
}

// NewWebhookResolver instancia y valida arquitectónicamente el inyector.
func NewWebhookResolver(targetURL, secretEnc string, customTimeout time.Duration, headers map[string]string) (*WebhookResolver, error) {
	if isSSRFVulnerable(targetURL) {
		return nil, fmt.Errorf("Invalid Webhook URL: potential SSRF vector mitigation")
	}

	// Forzar timeboxing límite de 2 segundos.
	t := customTimeout
	if t <= 0 || t > maxWebhookTimeout {
		t = maxWebhookTimeout
	}

	// Rehidratar secret para HMAC Firmas
	decryptedSecret, err := secretbox.Decrypt(secretEnc)
	if err != nil {
		return nil, fmt.Errorf("WebhookResolver failed to decrypt tenant secret: %w", err)
	}

	return &WebhookResolver{
		URL:          targetURL,
		SecretEnc:    secretEnc,
		Timeout:      t,
		Headers:      headers,
		parsedSecret: decryptedSecret,
	}, nil
}

// Name cumple Interface
func (w *WebhookResolver) Name() string {
	return "webhook"
}

// Resolve bloquea la ejecución, llama a un ente externo y empaqueta el Response al JWT.
func (w *WebhookResolver) Resolve(ctx context.Context, input ResolverInput) (any, error) {
	// 1. Compilación del Payload a enviar
	payloadBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed encoding resolver input: %w", err)
	}

	// 2. Generación de Firma HMAC (Previene MITM y falsificación ante el destino)
	mac := hmac.New(sha256.New, []byte(w.parsedSecret))
	timestamp := time.Now().Unix()
	msg := fmt.Sprintf("%d.%s", timestamp, string(payloadBytes))
	mac.Write([]byte(msg))
	signature := hex.EncodeToString(mac.Sum(nil))

	// 3. Empaque HTTP
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HelloJohn-Signature", signature)
	req.Header.Set("X-HelloJohn-Timestamp", strconv.FormatInt(timestamp, 10))

	// Map de headers flat provisto por config de ui
	for k, v := range w.Headers {
		req.Header.Add(k, v)
	}

	// 4. DoS Protection - Timeout
	client := &http.Client{
		Timeout: w.Timeout,
	}

	// Goroutine bloqueante esperando la API web externa
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webhook transport failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("webhook returned non-success code %d", resp.StatusCode)
	}

	// 5. Data Bloom Protection - Truncamos Body en memoria
	limitReader := io.LimitReader(resp.Body, maxWebhookBodySize)
	b, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("webhook payload read error: %w", err)
	}

	// 6. Decodificación Dinámica
	var claimVal any
	if err := json.Unmarshal(b, &claimVal); err != nil {
		return nil, fmt.Errorf("webhook return invalid json format: %w", err)
	}

	// Mapeo Inteligente:
	// Si el user devolvió un objeto crudo tipo `{"value": ["admin"]}`, sacamos la llave value.
	// Si devolvió map, raw string simple o array en body crudo, lo pasamos al JWT asi tal cual.
	if m, ok := claimVal.(map[string]any); ok {
		if val, exists := m["value"]; exists && len(m) == 1 {
			return val, nil
		}
	}

	return claimVal, nil
}
