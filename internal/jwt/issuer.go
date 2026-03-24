package jwt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/types"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TenantResolver es una función para mapear tenant ID (UUID) a slug.
// Se inyecta opcionalmente para resolver "tid" claims a slugs.
type TenantResolver func(ctx context.Context, tenantID string) (slug string, err error)

// Issuer firma tokens usando la clave activa del keystore persistente.
type Issuer struct {
	Iss            string              // "iss" base
	Keys           *PersistentKeystore // keystore persistente
	AccessTTL      time.Duration       // TTL por defecto de Access/ID (ej: 15m)
	TenantResolver TenantResolver      // opcional: para mapear tid→slug
}

func NewIssuer(iss string, ks *PersistentKeystore) *Issuer {
	return &Issuer{
		Iss:       iss,
		Keys:      ks,
		AccessTTL: 15 * time.Minute,
	}
}

// WithTenantResolver agrega un resolver de tenants.
func (i *Issuer) WithTenantResolver(resolver TenantResolver) *Issuer {
	i.TenantResolver = resolver
	return i
}

// GetIss returns the issuer string.
func (i *Issuer) GetIss() string {
	return i.Iss
}

// ActiveKID devuelve el KID activo actual.
func (i *Issuer) ActiveKID() (string, error) {
	kid, _, _, err := i.Keys.Active()
	return kid, err
}

// Keyfunc devuelve un jwt.Keyfunc que elige la pubkey por 'kid' del token (active/retiring).
func (i *Issuer) Keyfunc() jwtv5.Keyfunc {
	return func(t *jwtv5.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid != "" {
			return i.Keys.PublicKeyByKID(kid)
		}
		// Fallback: usar la activa
		_, _, pub, err := i.Keys.Active()
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(pub), nil
	}
}

// KeyfuncForTenant devuelve un jwt.Keyfunc tenant-aware que resuelve la pubkey por KID
// dentro del JWKS del tenant. Si no encuentra el KID, retorna error y el token falla.
// tenantSlug es el slug del tenant (ej: "acme"), no el UUID.
func (i *Issuer) KeyfuncForTenant(tenantSlug string) jwtv5.Keyfunc {
	return func(t *jwtv5.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("kid_missing")
		}
		// Buscar pubkey en JWKS del tenant usando su slug
		pub, err := i.Keys.PublicKeyByKIDForTenant(tenantSlug, kid)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(pub), nil
	}
}

// SignRaw firma un MapClaims arbitrario, setea header kid/typ y devuelve el JWT firmado.
func (i *Issuer) SignRaw(claims jwtv5.MapClaims) (string, string, error) {
	kid, priv, _, err := i.Keys.Active()
	if err != nil {
		return "", "", err
	}
	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"
	signed, err := tk.SignedString(priv)
	if err != nil {
		return "", "", err
	}
	return signed, kid, nil
}

// IssueAccess emite un Access Token con claims estándar + std (flat) y custom (anidado).
func (i *Issuer) IssueAccess(sub, aud string, std map[string]any, custom map[string]any) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(i.AccessTTL)

	kid, priv, _, err := i.Keys.Active()
	if err != nil {
		return "", time.Time{}, err
	}

	claims := jwtv5.MapClaims{
		"iss": i.Iss,
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
	}
	for k, v := range std {
		claims[k] = v
	}
	for k, v := range custom {
		claims[k] = v
	}
	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"

	signed, err := tk.SignedString(priv)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// IssueIDToken emite un ID Token OIDC con claims estándar y extras.
func (i *Issuer) IssueIDToken(sub, aud string, std map[string]any, extra map[string]any) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(i.AccessTTL)

	kid, priv, _, err := i.Keys.Active()
	if err != nil {
		return "", time.Time{}, err
	}

	claims := jwtv5.MapClaims{
		"iss": i.Iss,
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
	}
	for k, v := range std {
		claims[k] = v
	}
	for k, v := range extra {
		claims[k] = v
	}

	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"

	signed, err := tk.SignedString(priv)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// IssueAccessForTenant emite un Access Token para un tenant específico usando su clave activa
// y un issuer efectivo resuelto por configuración.
// tenantSlug identifica el tenant en el keystore (ej: "acme").
func (i *Issuer) IssueAccessForTenant(tenantSlug, iss, sub, aud string, std map[string]any, custom map[string]any) (string, time.Time, error) {
	return i.IssueAccessForTenantWithTTL(tenantSlug, iss, sub, aud, std, custom, 0)
}

// IssueAccessForTenantWithTTL emite un Access Token con TTL personalizado.
// Si ttlSeconds <= 0, usa el TTL por defecto del issuer.
func (i *Issuer) IssueAccessForTenantWithTTL(tenantSlug, iss, sub, aud string, std map[string]any, custom map[string]any, ttlSeconds int) (string, time.Time, error) {
	now := time.Now().UTC()

	// Use custom TTL if provided, otherwise use default
	ttl := i.AccessTTL
	if ttlSeconds > 0 {
		ttl = time.Duration(ttlSeconds) * time.Second
	}
	exp := now.Add(ttl)

	kid, priv, _, err := i.Keys.ActiveForTenant(tenantSlug)
	if err != nil {
		return "", time.Time{}, err
	}

	claims := jwtv5.MapClaims{
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
	}
	for k, v := range std {
		claims[k] = v
	}
	for k, v := range custom {
		claims[k] = v
	}
	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"

	signed, err := tk.SignedString(priv)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// IssueIDTokenForTenant emite un ID Token OIDC para un tenant específico.
// tenantSlug identifica el tenant en el keystore (ej: "acme").
func (i *Issuer) IssueIDTokenForTenant(tenantSlug, iss, sub, aud string, std map[string]any, extra map[string]any) (string, time.Time, error) {
	return i.IssueIDTokenForTenantWithTTL(tenantSlug, iss, sub, aud, std, extra, 0)
}

// IssueIDTokenForTenantWithTTL emite un ID Token OIDC con TTL personalizado.
// Si ttlSeconds <= 0, usa el TTL por defecto del issuer.
func (i *Issuer) IssueIDTokenForTenantWithTTL(tenantSlug, iss, sub, aud string, std map[string]any, extra map[string]any, ttlSeconds int) (string, time.Time, error) {
	now := time.Now().UTC()

	// Use custom TTL if provided, otherwise use default
	ttl := i.AccessTTL
	if ttlSeconds > 0 {
		ttl = time.Duration(ttlSeconds) * time.Second
	}
	exp := now.Add(ttl)

	kid, priv, _, err := i.Keys.ActiveForTenant(tenantSlug)
	if err != nil {
		return "", time.Time{}, err
	}

	claims := jwtv5.MapClaims{
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
	}
	for k, v := range std {
		claims[k] = v
	}
	for k, v := range extra {
		claims[k] = v
	}
	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"

	signed, err := tk.SignedString(priv)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// MintSessionToken issues a short-lived JWT derived from an active browser session.
// This token is intended for API calls from cookie-authenticated browser flows.
func (i *Issuer) MintSessionToken(sub, tenantID string, ttl time.Duration) (string, time.Time, error) {
	sub = strings.TrimSpace(sub)
	tenantID = strings.TrimSpace(tenantID)
	if sub == "" || tenantID == "" {
		return "", time.Time{}, errors.New("invalid_session_subject_or_tenant")
	}

	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	now := time.Now().UTC()
	exp := now.Add(ttl)

	kid, priv, _, err := i.Keys.Active()
	if err != nil {
		return "", time.Time{}, err
	}

	claims := jwtv5.MapClaims{
		"iss": i.Iss,
		"sub": sub,
		"aud": "session",
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
		"tid": tenantID,
		"typ": "session_token",
		"amr": []string{"session"},
		"scp": "openid profile email profile:read",
	}

	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"

	signed, err := tk.SignedString(priv)
	if err != nil {
		return "", time.Time{}, err
	}

	return signed, exp, nil
}

// JWKSJSON expone el JWKS actual (active+retiring)
func (i *Issuer) JWKSJSON() []byte {
	j, _ := i.Keys.JWKSJSON()
	return j
}

// Helpers defensivos para errores comunes
var (
	ErrInvalidIssuer   = errors.New("invalid_issuer")
	ErrInvalidAudience = errors.New("invalid_audience")
)

// ───────────────────────────────────────────────────────────────
// helpers para firmar claims arbitrarios EdDSA
// ───────────────────────────────────────────────────────────────

// SignEdDSA firma claims arbitrarios con la clave activa (no inyecta iss/exp/iat).
// Útil para firmar "state" de flows sociales, etc.
func (i *Issuer) SignEdDSA(claims map[string]any) (string, error) {
	mc := jwtv5.MapClaims{}
	for k, v := range claims {
		mc[k] = v
	}
	signed, _, err := i.SignRaw(mc)
	return signed, err
}

// ResolveIssuer construye el issuer efectivo por tenant según settings del control-plane.
// - Si override no está vacío, lo usa tal cual (sin trailing slash)
// - Path:   {base}/t/{slug}
// - Domain: futuro (por ahora igual que Path)
// - Global: base
// mode acepta string para compatibilidad con controlplane/v1.IssuerMode
func ResolveIssuer(baseURL string, mode string, tenantSlug, override string) string {
	if override != "" {
		return strings.TrimRight(override, "/")
	}
	base := strings.TrimRight(baseURL, "/")
	switch types.IssuerMode(mode) {
	case types.IssuerModePath:
		return fmt.Sprintf("%s/t/%s", base, tenantSlug)
	case types.IssuerModeDomain:
		// futuro: slug subdominio (requiere DNS)
		return fmt.Sprintf("%s/t/%s", base, tenantSlug) // por ahora
	default:
		return base // global
	}
}

// KeyfuncFromTokenClaims intenta derivar el tenant a partir de los claims (tid) o del iss
// (modo path /t/{slug}) y usa PublicKeyByKIDForTenant para validar la firma.
//
// Orden de resolución:
//  1. iss claim: parsear slug de .../t/{slug}/...
//  2. tid claim: si es UUID, requiere TenantResolver inyectado; si es slug, usar directo.
//  3. Si tenantSlug es vacío (token global sin tenant), usar keystore global.
//
// SEGURIDAD: Si tid es UUID y TenantResolver es nil, retorna error explícito en lugar
// de caer silenciosamente al keystore global (podría generar falso positivo de validación).
func (i *Issuer) KeyfuncFromTokenClaims() jwtv5.Keyfunc {
	return func(t *jwtv5.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("kid_missing")
		}

		var tenantSlug string
		if mc, ok := t.Claims.(jwtv5.MapClaims); ok {
			// 1) Intentar desde iss: .../t/{slug}
			if issRaw, okIss := mc["iss"].(string); okIss && issRaw != "" {
				if u, err := url.Parse(issRaw); err == nil {
					parts := strings.Split(strings.Trim(u.Path, "/"), "/")
					for idx := 0; idx < len(parts)-1; idx++ {
						if parts[idx] == "t" && idx+1 < len(parts) {
							tenantSlug = parts[idx+1]
						}
					}
				}
			}

			// 2) Si no se obtuvo desde iss, usar tid.
			if tenantSlug == "" {
				if v, okTid := mc["tid"].(string); okTid && v != "" {
					if _, err := uuid.Parse(v); err == nil {
						// tid es UUID: requiere TenantResolver para mapear a slug.
						if i.TenantResolver == nil {
							// FIX: Error explícito en lugar de fallback silencioso.
							// Un token con tid=UUID emitido por este sistema SIEMPRE
							// debe validarse con la clave del tenant, nunca con la global.
							return nil, fmt.Errorf("tenant_resolver_required_for_uuid_tid: tid=%s kid=%s", v, kid)
						}
						if slug, err := i.TenantResolver(context.Background(), v); err == nil {
							tenantSlug = slug
						} else {
							return nil, fmt.Errorf("tenant_not_found: tid=%s: %w", v, err)
						}
					} else {
						// tid parece un slug (tokens históricos o tokens de testing)
						tenantSlug = v
					}
				}
			}
		}

		// 3) Si tenemos tenantSlug, buscar en el Tenant Keyring.
		if tenantSlug != "" {
			pub, err := i.Keys.PublicKeyByKIDForTenant(tenantSlug, kid)
			if err == nil {
				return ed25519.PublicKey(pub), nil
			}
			// Si el tenant keyring falla, NO caer al global — retornar error descriptivo.
			return nil, fmt.Errorf("kid_not_found_for_tenant: %s (tenant=%s)", kid, tenantSlug)
		}

		// 4) Token genuinamente sin tenant (admin global, token de servicio sin tid ni /t/{slug}).
		// Usar keystore global solo en este caso legítimo.
		pub, err := i.Keys.PublicKeyByKID(kid)
		if err != nil {
			return nil, fmt.Errorf("kid_not_found: %s (no tenant context)", kid)
		}
		return ed25519.PublicKey(pub), nil
	}
}

// IssueAdminAccess emite un Access Token para un administrador.
// El token incluye claims específicos de admin: admin_type y tenants asignados.
// Audience siempre es "hellojohn:admin".
func (i *Issuer) IssueAdminAccess(ctx context.Context, claims AdminAccessClaims) (string, int, error) {
	now := time.Now().UTC()
	exp := now.Add(i.AccessTTL)

	kid, priv, _, err := i.Keys.Active()
	if err != nil {
		return "", 0, err
	}

	jwtClaims := jwtv5.MapClaims{
		"iss":        i.Iss,
		"sub":        claims.AdminID,
		"aud":        "hellojohn:admin",
		"email":      claims.Email,
		"admin_type": claims.AdminType,
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
		"exp":        exp.Unix(),
	}

	// Solo incluir tenants si no está vacío (tenant admin)
	if len(claims.Tenants) > 0 {
		jwtClaims["tenants"] = claims.Tenants
	}
	if len(claims.Perms) > 0 {
		jwtClaims["perms"] = claims.Perms
	}

	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, jwtClaims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"

	signed, err := tk.SignedString(priv)
	if err != nil {
		return "", 0, err
	}

	expiresIn := int(i.AccessTTL.Seconds())
	return signed, expiresIn, nil
}

// VerifyAdminAccess verifica un admin access token y retorna los claims.
func (i *Issuer) VerifyAdminAccess(ctx context.Context, token string) (*AdminAccessClaims, error) {
	// Parse y validar firma usando el keystore
	rawClaims, err := ParseEdDSA(token, i, i.Iss)
	if err != nil {
		return nil, err
	}

	// Verificar audience
	if aud, ok := rawClaims["aud"].(string); !ok || aud != "hellojohn:admin" {
		return nil, ErrInvalidAudience
	}

	// Extraer claims específicos de admin
	adminID, _ := rawClaims["sub"].(string)
	email, _ := rawClaims["email"].(string)
	adminType, _ := rawClaims["admin_type"].(string)

	if adminID == "" || email == "" || adminType == "" {
		return nil, errors.New("missing required admin claims")
	}

	claims := &AdminAccessClaims{
		AdminID:   adminID,
		Email:     email,
		AdminType: adminType,
	}

	// Extraer tenants si existen (opcional para global admins)
	// Soporta tanto el nuevo formato [{slug, role}] como el legacy [string] para backward compat.
	if tenantsRaw, ok := rawClaims["tenants"]; ok {
		switch v := tenantsRaw.(type) {
		case []interface{}:
			for _, t := range v {
				switch entry := t.(type) {
				case map[string]interface{}:
					// Nuevo formato: {"tenant_id": "uuid", "role": "owner"}
					id, _ := entry["tenant_id"].(string)
					role, _ := entry["role"].(string)
					if id != "" {
						claims.Tenants = append(claims.Tenants, TenantAccessClaim{ID: id, Role: role})
					}
				case string:
					// Legacy formato: solo el slug — asignar role "owner" por backward compat
					if entry != "" {
						claims.Tenants = append(claims.Tenants, TenantAccessClaim{ID: entry, Role: "owner"})
					}
				}
			}
		}
	}
	if permsRaw, ok := rawClaims["perms"]; ok {
		switch v := permsRaw.(type) {
		case []string:
			claims.Perms = v
		case []interface{}:
			for _, p := range v {
				if s, ok := p.(string); ok {
					claims.Perms = append(claims.Perms, s)
				}
			}
		}
	}

	return claims, nil
}

// ─── Cloud Access Tokens ───

// CloudAccessClaims holds claims for a cloud panel access token.
type CloudAccessClaims struct {
	CloudUserID string
	Email       string
}

// IssueCloudToken emits an access token for the cloud panel.
// Claims: sub=cloudUserID, email, aud=hellojohn:cloud, typ=cloud_access_token.
func (i *Issuer) IssueCloudToken(userID, email string, ttl time.Duration) (string, int64, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)

	kid, priv, _, err := i.Keys.Active()
	if err != nil {
		return "", 0, err
	}

	jwtClaims := jwtv5.MapClaims{
		"iss":   i.Iss + "/cloud",
		"sub":   userID,
		"aud":   "hellojohn:cloud",
		"email": email,
		"typ":   "cloud_access_token",
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   exp.Unix(),
	}

	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, jwtClaims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"

	signed, err := tk.SignedString(priv)
	if err != nil {
		return "", 0, err
	}

	return signed, exp.Unix(), nil
}

// VerifyCloudToken verifies a cloud access token and returns its claims.
// Returns error if the token is invalid or is not a cloud_access_token.
func (i *Issuer) VerifyCloudToken(token string) (map[string]any, error) {
	parser := jwtv5.NewParser(
		jwtv5.WithValidMethods([]string{"EdDSA"}),
	)

	parsed, err := parser.Parse(token, i.Keyfunc())
	if err != nil {
		return nil, fmt.Errorf("cloud token invalid: %w", err)
	}

	rawClaims, ok := parsed.Claims.(jwtv5.MapClaims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("cloud token malformed")
	}

	claims := map[string]any(rawClaims)

	// Must be a cloud token
	if claims["typ"] != "cloud_access_token" {
		return nil, fmt.Errorf("not a cloud_access_token")
	}

	// Must have correct audience
	switch aud := claims["aud"].(type) {
	case string:
		if aud != "hellojohn:cloud" {
			return nil, fmt.Errorf("invalid audience")
		}
	case []interface{}:
		found := false
		for _, a := range aud {
			if s, ok := a.(string); ok && s == "hellojohn:cloud" {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("invalid audience")
		}
	default:
		return nil, fmt.Errorf("invalid audience")
	}

	return claims, nil
}
