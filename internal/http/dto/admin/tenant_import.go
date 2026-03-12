package admin

// ─── Import/Export DTOs ───

// TenantImportRequest representa los datos para importar configuración de un tenant.
type TenantImportRequest struct {
	Version    string                  `json:"version"`              // "1.0"
	ExportedAt string                  `json:"exportedAt,omitempty"` // ISO8601 timestamp
	Mode       string                  `json:"mode,omitempty"`       // "merge" | "replace" (default: merge)
	Tenant     *TenantImportInfo       `json:"tenant,omitempty"`
	Settings   *TenantSettingsResponse `json:"settings,omitempty"`
	Clients    []ClientImportData      `json:"clients,omitempty"`
	Scopes     []ScopeImportData       `json:"scopes,omitempty"`
	Users      []UserImportData        `json:"users,omitempty"`
	Roles      []RoleImportData        `json:"roles,omitempty"`
	Webhooks   []WebhookExportData     `json:"webhooks,omitempty"`
	// Secrets secretos en texto plano para re-cifrar en el host destino.
	// Sólo presente en exports completos o pushes directos entre instancias.
	Secrets *TenantSecretsBlock `json:"secrets,omitempty"`
}

// TenantImportInfo información básica del tenant a importar.
type TenantImportInfo struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name,omitempty"`
	Language    string `json:"language,omitempty"`
}

// ClientImportData datos de cliente para import.
type ClientImportData struct {
	ClientID      string   `json:"client_id"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	ClientType    string   `json:"client_type"` // "public" | "confidential"
	RedirectURIs  []string `json:"redirect_uris,omitempty"`
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	TokenTTL      int      `json:"token_ttl,omitempty"`
	RefreshTTL    int      `json:"refresh_ttl,omitempty"`
}

// ScopeImportData datos de scope para import.
type ScopeImportData struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	System      bool     `json:"system,omitempty"`
}

// UserImportData datos de usuario para import.
// NOTA: No se importan passwords encriptados por seguridad.
type UserImportData struct {
	Email         string                 `json:"email"`
	Username      string                 `json:"username,omitempty"`
	EmailVerified bool                   `json:"email_verified,omitempty"`
	Disabled      bool                   `json:"disabled,omitempty"`
	Roles         []string               `json:"roles,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	// SetPasswordOnImport: si true, se genera password temporal
	SetPasswordOnImport bool `json:"set_password_on_import,omitempty"`
}

// RoleImportData datos de rol para import.
type RoleImportData struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	InheritsFrom string   `json:"inherits_from,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
}

// ─── Import Validation Response ───

// ImportValidationResult resultado de validación de import (dry-run).
type ImportValidationResult struct {
	Valid     bool           `json:"valid"`
	Errors    []string       `json:"errors,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
	Conflicts []ConflictInfo `json:"conflicts,omitempty"`
	Summary   ImportSummary  `json:"summary"`
}

// ConflictInfo información sobre un conflicto detectado.
type ConflictInfo struct {
	Type       string `json:"type"`       // "client", "scope", "user", "role"
	Identifier string `json:"identifier"` // ID o nombre del recurso en conflicto
	Existing   string `json:"existing"`   // Descripción del existente
	Incoming   string `json:"incoming"`   // Descripción del entrante
	Action     string `json:"action"`     // "skip" | "overwrite" | "merge"
}

// ImportSummary resumen de qué se importará.
type ImportSummary struct {
	TenantName       string `json:"tenant_name"`
	SettingsIncluded bool   `json:"settings_included"`
	ClientsCount     int    `json:"clients_count"`
	ScopesCount      int    `json:"scopes_count"`
	UsersCount       int    `json:"users_count"`
	RolesCount       int    `json:"roles_count"`
}

// ─── Import Result Response ───

// ImportResultResponse resultado de una operación de import.
type ImportResultResponse struct {
	Success         bool          `json:"success"`
	Message         string        `json:"message,omitempty"`
	TenantID        string        `json:"tenant_id,omitempty"`
	TenantSlug      string        `json:"tenant_slug,omitempty"`
	ItemsImported   ImportCounts  `json:"items_imported"`
	ItemsSkipped    ImportCounts  `json:"items_skipped"`
	Errors          []ImportError `json:"errors,omitempty"`
	UsersNeedingPwd []string      `json:"users_needing_password,omitempty"` // Emails de usuarios que necesitan resetear password
}

// ImportCounts conteo de items procesados.
type ImportCounts struct {
	Settings int `json:"settings"`
	Clients  int `json:"clients"`
	Scopes   int `json:"scopes"`
	Users    int `json:"users"`
	Roles    int `json:"roles"`
}

// ImportError error durante importación de un item específico.
type ImportError struct {
	Type       string `json:"type"`       // "client", "scope", "user", "role", "settings"
	Identifier string `json:"identifier"` // ID o nombre del recurso
	Error      string `json:"error"`      // Mensaje de error
}

// ─── Export Options ───

// ExportOptionsRequest opciones para exportar configuración.
type ExportOptionsRequest struct {
	IncludeSettings bool `json:"include_settings"`
	IncludeClients  bool `json:"include_clients"`
	IncludeScopes   bool `json:"include_scopes"`
	IncludeRoles    bool `json:"include_roles"`
	// IncludeSecrets descifra y exporta todos los secretos en texto plano.
	// Sólo para operaciones de migración. El caller es responsable de proteger el resultado.
	IncludeSecrets bool `json:"include_secrets"`
}

// WebhookExportData represents a webhook endpoint for export/import.
// The signing secret is never included here; it goes into TenantSecretsBlock.WebhookSecrets.
type WebhookExportData struct {
	ID      string   `json:"id"`
	URL     string   `json:"url"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

// TenantExportResponse respuesta de export completo.
type TenantExportResponse struct {
	Version    string                  `json:"version"`
	ExportedAt string                  `json:"exportedAt"`
	Tenant     *TenantImportInfo       `json:"tenant"`
	Settings   *TenantSettingsResponse `json:"settings,omitempty"`
	Clients    []ClientImportData      `json:"clients,omitempty"`
	Scopes     []ScopeImportData       `json:"scopes,omitempty"`
	Roles      []RoleImportData        `json:"roles,omitempty"`
	Webhooks   []WebhookExportData     `json:"webhooks,omitempty"`
	// Secrets sólo está presente cuando IncludeSecrets=true.
	// Contiene todos los secretos descifrados. Tratar como credencial.
	Secrets *TenantSecretsBlock `json:"secrets,omitempty"`
}

// TenantSecretsBlock contiene todos los secretos del tenant en texto plano.
// Se usa para migración completa entre instancias. Al importar, cada secreto
// es re-cifrado con la SECRETBOX_MASTER_KEY del host destino.
type TenantSecretsBlock struct {
	// Credencial del servidor SMTP del tenant
	SMTPPassword string `json:"smtp_password,omitempty"`
	// EmailProvider API key del tenant (resend/sendgrid/mailgun, etc.)
	EmailProviderAPIKey string `json:"email_provider_api_key,omitempty"`
	// EmailProvider SMTP password del tenant (cuando provider=smtp)
	EmailProviderSMTPPassword string `json:"email_provider_smtp_password,omitempty"`
	// DSN completo de la base de datos del tenant (incluye usuario/contraseña)
	UserDBDSN string `json:"user_db_dsn,omitempty"`
	// Contraseña del servidor de cache (Redis, etc.)
	CachePassword string `json:"cache_password,omitempty"`
	// Client secrets de proveedores sociales
	GoogleSecret    string `json:"google_secret,omitempty"`
	GitHubSecret    string `json:"github_secret,omitempty"`
	FacebookSecret  string `json:"facebook_secret,omitempty"`
	MicrosoftSecret string `json:"microsoft_secret,omitempty"`
	DiscordSecret   string `json:"discord_secret,omitempty"`
	LinkedInSecret  string `json:"linkedin_secret,omitempty"`
	// Providers OIDC custom: map[provider_name] → client_secret
	CustomOIDCSecrets map[string]string `json:"custom_oidc_secrets,omitempty"`
	// Client secrets OAuth2: map[client_id] → secret
	ClientSecrets map[string]string `json:"client_secrets,omitempty"`
	// SMS / MFA
	TwilioAccountSID string `json:"twilio_account_sid,omitempty"`
	TwilioAuthToken  string `json:"twilio_auth_token,omitempty"`
	VonageAPIKey     string `json:"vonage_api_key,omitempty"`
	VonageAPISecret  string `json:"vonage_api_secret,omitempty"`
	// Webhook signing secrets: map[webhook_id] → plain secret
	WebhookSecrets map[string]string `json:"webhook_secrets,omitempty"`
}

// PushTenantRequest petición para enviar un tenant directamente a otra instancia HelloJohn.
// Los secretos nunca pasan por el browser: el source hace el HTTP POST server-to-server.
type PushTenantRequest struct {
	// InstanceID UUID de una instancia ya registrada en este sistema (mode: picker).
	// Si se especifica, el backend usa su BaseURL y descifra su APIKey internamente.
	// TargetURL y APIKey se ignoran cuando InstanceID está presente.
	InstanceID string `json:"instance_id,omitempty"`
	// TargetURL URL base de la instancia HelloJohn destino (modo manual).
	TargetURL string `json:"target_url,omitempty"`
	// APIKey clave de API con permisos admin en la instancia destino (modo manual).
	APIKey string `json:"api_key,omitempty"`
	// IncludeSecrets incluye y transfiere secretos en el push (recomendado para replicas exactas)
	IncludeSecrets bool `json:"include_secrets"`
	// Options controla qué partes del tenant se incluyen
	Options PushTenantOptions `json:"options"`
}

// PushTenantOptions opciones para el push de tenant.
type PushTenantOptions struct {
	Clients bool `json:"clients"`
	Scopes  bool `json:"scopes"`
	Roles   bool `json:"roles"`
}

// PushTenantResponse resultado del push directo a otra instancia.
type PushTenantResponse struct {
	Success    bool   `json:"success"`
	TenantID   string `json:"tenant_id,omitempty"`
	TenantSlug string `json:"tenant_slug,omitempty"`
	Message    string `json:"message,omitempty"`
}
