package social

import (
	"errors"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// StateClaims contains the claims for social login state JWT.
type StateClaims struct {
	Provider    string `json:"provider"`
	TenantSlug  string `json:"tenant_slug"`
	ClientID    string `json:"cid"`
	RedirectURI string `json:"redir,omitempty"`
	Nonce       string `json:"nonce"`
	jwtv5.RegisteredClaims
}

// StateAudience is the expected audience for social state tokens.
const StateAudience = "social-state"

// StateAudienceLegacy is the legacy audience for backward compatibility.
const StateAudienceLegacy = "google-state"

// StateSigner interface for signing state JWTs.
type StateSigner interface {
	SignState(claims StateClaims) (string, error)
	ParseState(tokenString string) (*StateClaims, error)
}

// Errors for state operations.
var (
	ErrStateInvalid  = errors.New("invalid state token")
	ErrStateExpired  = errors.New("state token expired")
	ErrStateIssuer   = errors.New("state issuer mismatch")
	ErrStateAudience = errors.New("state audience mismatch")
	ErrStateProvider = errors.New("state provider mismatch")
)

// IssuerAdapter adapts jwt.Issuer to StateSigner.
type IssuerAdapter struct {
	Issuer interface {
		SignRaw(claims jwtv5.MapClaims) (string, string, error)
		Keyfunc() jwtv5.Keyfunc
		Iss() string
	}
	StateTTL time.Duration
}

// SignState signs a state JWT.
func (a *IssuerAdapter) SignState(claims StateClaims) (string, error) {
	now := time.Now().UTC()
	mapClaims := jwtv5.MapClaims{
		"iss":         a.Issuer.Iss(),
		"aud":         StateAudience,
		"exp":         now.Add(a.StateTTL).Unix(),
		"iat":         now.Unix(),
		"nbf":         now.Unix(),
		"provider":    claims.Provider,
		"tenant_slug": claims.TenantSlug,
		"cid":         claims.ClientID,
		"nonce":       claims.Nonce,
	}
	if claims.RedirectURI != "" {
		mapClaims["redir"] = claims.RedirectURI
	}

	signed, _, err := a.Issuer.SignRaw(mapClaims)
	return signed, err
}

// ParseState parses and validates a state JWT.
func (a *IssuerAdapter) ParseState(tokenString string) (*StateClaims, error) {
	tk, err := jwtv5.Parse(tokenString, a.Issuer.Keyfunc(), jwtv5.WithValidMethods([]string{"EdDSA"}))
	if err != nil || !tk.Valid {
		return nil, ErrStateInvalid
	}

	mapClaims, ok := tk.Claims.(jwtv5.MapClaims)
	if !ok {
		return nil, ErrStateInvalid
	}

	// Validate issuer
	if iss, _ := mapClaims["iss"].(string); iss != a.Issuer.Iss() {
		return nil, ErrStateIssuer
	}

	// Validate audience (accept both new and legacy)
	aud, _ := mapClaims["aud"].(string)
	if aud != StateAudience && aud != StateAudienceLegacy {
		return nil, ErrStateAudience
	}

	// Check expiration with 30s grace
	if expf, ok := mapClaims["exp"].(float64); ok {
		if time.Unix(int64(expf), 0).Before(time.Now().Add(-30 * time.Second)) {
			return nil, ErrStateExpired
		}
	}

	// Extract claims
	claims := &StateClaims{
		Provider:    getString(mapClaims, "provider"),
		TenantSlug:  getString(mapClaims, "tenant_slug"),
		ClientID:    getString(mapClaims, "cid"),
		RedirectURI: getString(mapClaims, "redir"),
		Nonce:       getString(mapClaims, "nonce"),
	}

	return claims, nil
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// issuerWrapper wraps jwt.Issuer to match the IssuerAdapter interface.
type issuerWrapper struct {
	iss      string
	keyfunc  jwtv5.Keyfunc
	signRaw  func(claims jwtv5.MapClaims) (string, string, error)
}

func (w *issuerWrapper) Iss() string {
	return w.iss
}

func (w *issuerWrapper) Keyfunc() jwtv5.Keyfunc {
	return w.keyfunc
}

func (w *issuerWrapper) SignRaw(claims jwtv5.MapClaims) (string, string, error) {
	return w.signRaw(claims)
}

// NewIssuerAdapter creates an IssuerAdapter from a jwt.Issuer struct.
// This helper wraps the struct to match the interface expected by IssuerAdapter.
func NewIssuerAdapter(issuer IssuerStruct, stateTTL time.Duration) *IssuerAdapter {
	return &IssuerAdapter{
		Issuer: &issuerWrapper{
			iss:     issuer.GetIss(),
			keyfunc: issuer.Keyfunc(),
			signRaw: issuer.SignRaw,
		},
		StateTTL: stateTTL,
	}
}

// IssuerStruct represents the expected struct interface for jwt.Issuer.
type IssuerStruct interface {
	Keyfunc() jwtv5.Keyfunc
	SignRaw(claims jwtv5.MapClaims) (string, string, error)
	GetIss() string
}
