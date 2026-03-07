package google

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

const discoveryURL = "https://accounts.google.com/.well-known/openid-configuration"

type discoveryDoc struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"` // base64url
	E   string `json:"e"` // base64url
}
type jwks struct {
	Keys []jwk `json:"keys"`
}

type OIDC struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	http  *http.Client
	mu    sync.RWMutex
	disc  *discoveryDoc
	discU time.Time

	jwks     *jwks
	jwksAt   time.Time
	jwksETag string
}

func New(clientID, clientSecret, redirectURL string, scopes []string) *OIDC {
	return &OIDC{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		http:         &http.Client{Timeout: 10 * time.Second},
	}
}

func (g *OIDC) discovery(ctx context.Context) (*discoveryDoc, error) {
	g.mu.RLock()
	disc := g.disc
	stale := time.Since(g.discU) > 24*time.Hour
	g.mu.RUnlock()
	if disc != nil && !stale {
		return disc, nil
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var dd discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&dd); err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.disc = &dd
	g.discU = time.Now()
	g.mu.Unlock()
	return &dd, nil
}

func (g *OIDC) getJWKS(ctx context.Context, uri string) (*jwks, error) {
	g.mu.RLock()
	j := g.jwks
	age := time.Since(g.jwksAt)
	g.mu.RUnlock()
	if j != nil && age < 1*time.Hour {
		return j, nil
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if g.jwksETag != "" {
		req.Header.Set("If-None-Match", g.jwksETag)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		g.mu.Lock()
		out := g.jwks
		g.jwksAt = time.Now()
		g.mu.Unlock()
		return out, nil
	}

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("jwks http %d", resp.StatusCode)
	}
	var jj jwks
	if err := json.NewDecoder(resp.Body).Decode(&jj); err != nil {
		return nil, err
	}

	g.mu.Lock()
	g.jwks = &jj
	g.jwksAt = time.Now()
	g.jwksETag = resp.Header.Get("ETag")
	g.mu.Unlock()
	return &jj, nil
}

func (g *OIDC) rsaKeyForKid(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	disc, err := g.discovery(ctx)
	if err != nil {
		return nil, err
	}
	jwks, err := g.getJWKS(ctx, disc.JWKSURI)
	if err != nil {
		return nil, err
	}
	for _, k := range jwks.Keys {
		if k.Kid == kid && strings.EqualFold(k.Kty, "RSA") {
			nb, err := base64.RawURLEncoding.DecodeString(k.N)
			if err != nil {
				return nil, err
			}
			eb, err := base64.RawURLEncoding.DecodeString(k.E)
			if err != nil {
				return nil, err
			}
			n := new(big.Int).SetBytes(nb)
			var e int
			if len(eb) == 0 {
				e = 65537
			} else {
				// big-endian bytes to int
				e = 0
				for _, b := range eb {
					e = (e << 8) | int(b)
				}
			}
			return &rsa.PublicKey{N: n, E: e}, nil
		}
	}
	return nil, errors.New("kid not found")
}

// AuthURL construye la URL de autorización
func (g *OIDC) AuthURL(ctx context.Context, state, nonce string) (string, error) {
	disc, err := g.discovery(ctx)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(disc.AuthEndpoint)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", g.ClientID)
	q.Set("redirect_uri", g.RedirectURL)
	q.Set("scope", strings.Join(g.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	// Opcionales útiles
	q.Set("access_type", "offline")
	q.Set("include_granted_scopes", "true")
	// UX opcional:
	// q.Set("prompt", "select_account")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	RefreshTok  string `json:"refresh_token,omitempty"`
}

func (g *OIDC) ExchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
	disc, err := g.discovery(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", g.ClientID)
	form.Set("client_secret", g.ClientSecret)
	form.Set("redirect_uri", g.RedirectURL)

	req, _ := http.NewRequestWithContext(ctx, "POST", disc.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var b struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&b)
		return nil, fmt.Errorf("token http %d: %s %s", resp.StatusCode, b.Error, b.ErrorDescription)
	}
	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

type IDClaims struct {
	Sub           string          `json:"sub"`
	Iss           string          `json:"iss"`
	Aud           any             `json:"aud"` // string or []string
	Exp           int64           `json:"exp"`
	Iat           int64           `json:"iat"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"email_verified"`
	Name          string          `json:"name"`
	GivenName     string          `json:"given_name"`
	FamilyName    string          `json:"family_name"`
	Picture       string          `json:"picture"`
	Locale        string          `json:"locale"`
	Nonce         string          `json:"nonce"`
	Hd            string          `json:"hd,omitempty"`
	Azp           string          `json:"azp,omitempty"`
	Scope         []string        `json:"-"`
	Raw           jwtv5.MapClaims `json:"-"`
}

// VerifyIDToken valida firma, iss, aud y nonce. Devuelve claims.
func (g *OIDC) VerifyIDToken(ctx context.Context, idToken string, expectedNonce string) (*IDClaims, error) {
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("bad jwt format")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, err
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unexpected alg: %s", header.Alg)
	}

	key, err := g.rsaKeyForKid(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	tok, err := jwtv5.Parse(idToken, func(t *jwtv5.Token) (any, error) { return key, nil }, jwtv5.WithValidMethods([]string{"RS256"}))
	if err != nil || !tok.Valid {
		return nil, errors.New("invalid id_token")
	}

	claims, ok := tok.Claims.(jwtv5.MapClaims)
	if !ok {
		return nil, errors.New("claims type")
	}

	// iss
	iss, _ := claims["iss"].(string)
	if iss != "https://accounts.google.com" && iss != "accounts.google.com" {
		return nil, fmt.Errorf("bad iss: %s", iss)
	}
	// aud
	audOK := false
	switch a := claims["aud"].(type) {
	case string:
		audOK = (a == g.ClientID)
	case []any:
		for _, v := range a {
			if s, _ := v.(string); s == g.ClientID {
				audOK = true
				break
			}
		}
	}
	if !audOK {
		return nil, errors.New("bad aud")
	}
	// nonce
	if expectedNonce != "" {
		if got, _ := claims["nonce"].(string); got != expectedNonce {
			return nil, errors.New("bad nonce")
		}
	}
	// exp
	if expf, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(expf), 0).Before(time.Now().Add(-30 * time.Second)) {
			return nil, errors.New("token expired")
		}
	}

	out := &IDClaims{
		Raw:           claims,
		Sub:           strClaim(claims, "sub"),
		Iss:           iss,
		Email:         strClaim(claims, "email"),
		EmailVerified: boolClaim(claims, "email_verified"),
		Name:          strClaim(claims, "name"),
		GivenName:     strClaim(claims, "given_name"),
		FamilyName:    strClaim(claims, "family_name"),
		Picture:       strClaim(claims, "picture"),
		Locale:        strClaim(claims, "locale"),
		Nonce:         strClaim(claims, "nonce"),
	}
	return out, nil
}

func strClaim(m jwtv5.MapClaims, k string) string {
	if s, _ := m[k].(string); s != "" {
		return s
	}
	return ""
}
func boolClaim(m jwtv5.MapClaims, k string) bool {
	if b, ok := m[k].(bool); ok {
		return b
	}
	return false
}
