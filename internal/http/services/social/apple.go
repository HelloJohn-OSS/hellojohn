package social

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

const (
	appleIssuer             = "https://appleid.apple.com"
	appleJWKSURL            = "https://appleid.apple.com/auth/keys"
	defaultAppleJWKSCacheTT = 1 * time.Hour
)

// AppleFactory implementa ProviderFactory para Sign In With Apple.
type AppleFactory struct {
	TenantProvider TenantProvider
}

func (f *AppleFactory) Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error) {
	if f.TenantProvider == nil {
		return nil, fmt.Errorf("tenant provider not configured")
	}

	tenant, err := f.TenantProvider.GetTenant(ctx, tenantSlug)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	settings := &tenant.Settings
	if settings.SocialProviders == nil {
		return nil, fmt.Errorf("social providers not configured")
	}
	if !settings.SocialProviders.AppleEnabled {
		return nil, fmt.Errorf("apple not enabled for tenant")
	}

	clientID := settings.SocialProviders.AppleClientID
	teamID := settings.SocialProviders.AppleTeamID
	keyID := settings.SocialProviders.AppleKeyID
	privateKeyEnc := settings.SocialProviders.ApplePrivateKeyEnc

	if clientID == "" || teamID == "" || keyID == "" {
		return nil, fmt.Errorf("apple configuration incomplete (client_id, team_id, key_id required)")
	}

	// Decrypt the P8 private key
	privateKeyPEM, err := decryptSecret(privateKeyEnc, "apple")
	if err != nil {
		return nil, err
	}

	// Generate the client secret JWT on-the-fly
	clientSecret, err := generateAppleClientSecret(teamID, clientID, keyID, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("apple client secret generation: %w", err)
	}

	redirectURL := fmt.Sprintf("%s/v2/auth/social/apple/callback", strings.TrimRight(baseURL, "/"))
	return &appleAdapter{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		httpClient:   sharedSocialHTTPClient(),
		issuer:       appleIssuer,
		jwksURL:      appleJWKSURL,
		jwksTTL:      defaultAppleJWKSCacheTT,
	}, nil
}

// generateAppleClientSecret creates a signed JWT to use as client_secret
// for Apple's OAuth token endpoint. Apple requires ES256 signing with
// a P8 private key.
func generateAppleClientSecret(teamID, clientID, keyID, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid P8 key: failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("invalid P8 key: %w", err)
	}

	now := time.Now()
	claims := jwtv5.MapClaims{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(150 * 24 * time.Hour).Unix(), // Max ~5 months
		"aud": appleIssuer,
		"sub": clientID,
	}
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
	token.Header["kid"] = keyID

	return token.SignedString(key)
}

type appleAdapter struct {
	clientID, clientSecret, redirectURL string
	httpClient                          *http.Client
	issuer                              string
	jwksURL                             string
	jwksTTL                             time.Duration

	mu       sync.RWMutex
	jwks     *appleJWKS
	jwksAt   time.Time
	jwksETag string
}

type appleJWKS struct {
	Keys []appleJWK `json:"keys"`
}

type appleJWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"` // base64url modulus
	E   string `json:"e"` // base64url exponent
}

type appleJWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// AuthURL uses response_mode=form_post as required by Apple.
func (a *appleAdapter) AuthURL(_ context.Context, state, nonce string) (string, error) {
	params := url.Values{
		"client_id":     {a.clientID},
		"redirect_uri":  {a.redirectURL},
		"response_type": {"code id_token"},
		"scope":         {"name email"},
		"state":         {state},
		"nonce":         {nonce},
		"response_mode": {"form_post"},
	}
	return "https://appleid.apple.com/auth/authorize?" + params.Encode(), nil
}

func (a *appleAdapter) ExchangeCode(ctx context.Context, code string) (*OIDCTokens, error) {
	data := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {a.redirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://appleid.apple.com/auth/token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("apple token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("apple token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apple token exchange: status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("apple token decode: %w", err)
	}

	return &OIDCTokens{
		AccessToken:  tok.AccessToken,
		IDToken:      tok.IDToken,
		RefreshToken: tok.RefreshToken,
		ExpiresIn:    tok.ExpiresIn,
	}, nil
}

// VerifyIDToken validates Apple's id_token against Apple's JWKS and required claims.
func (a *appleAdapter) VerifyIDToken(ctx context.Context, idToken, expectedNonce string) (*OIDCClaims, error) {
	if idToken == "" {
		return nil, fmt.Errorf("no id_token received from apple")
	}

	header, err := parseAppleJWTHeader(idToken)
	if err != nil {
		return nil, fmt.Errorf("apple id_token header: %w", err)
	}
	if header.Alg != jwtv5.SigningMethodRS256.Alg() {
		return nil, fmt.Errorf("apple id_token unexpected alg: %s", header.Alg)
	}
	if strings.TrimSpace(header.Kid) == "" {
		return nil, errors.New("apple id_token missing kid")
	}

	pubKey, err := a.rsaKeyForKID(ctx, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("apple jwks key lookup: %w", err)
	}

	token, err := jwtv5.Parse(
		idToken,
		func(t *jwtv5.Token) (any, error) {
			if t.Method.Alg() != jwtv5.SigningMethodRS256.Alg() {
				return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
			}
			return pubKey, nil
		},
		jwtv5.WithValidMethods([]string{jwtv5.SigningMethodRS256.Alg()}),
	)
	if err != nil {
		return nil, fmt.Errorf("apple id_token verification failed: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("apple id_token invalid")
	}

	claims, ok := token.Claims.(jwtv5.MapClaims)
	if !ok {
		return nil, fmt.Errorf("apple id_token: unexpected claims type")
	}

	issuer := strClaim(claims, "iss")
	if issuer != a.issuer {
		return nil, fmt.Errorf("apple id_token bad issuer: %s", issuer)
	}
	if !hasAudience(claims["aud"], a.clientID) {
		return nil, errors.New("apple id_token bad audience")
	}
	if expectedNonce != "" {
		if nonce := strClaim(claims, "nonce"); nonce != expectedNonce {
			return nil, errors.New("apple id_token bad nonce")
		}
	}
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now().Add(-30 * time.Second)) {
			return nil, errors.New("apple id_token expired")
		}
	}

	return &OIDCClaims{
		Sub:           strClaim(claims, "sub"),
		Email:         strClaim(claims, "email"),
		EmailVerified: boolClaim(claims["email_verified"]),
		Name:          strClaim(claims, "name"),
		GivenName:     strClaim(claims, "given_name"),
		FamilyName:    strClaim(claims, "family_name"),
		Locale:        strClaim(claims, "locale"),
		Nonce:         strClaim(claims, "nonce"),
	}, nil
}

func parseAppleJWTHeader(idToken string) (*appleJWTHeader, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("bad jwt format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var header appleJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return &header, nil
}

func (a *appleAdapter) rsaKeyForKID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	jwks, err := a.getJWKS(ctx)
	if err != nil {
		return nil, err
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid && strings.EqualFold(key.Kty, "RSA") {
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, fmt.Errorf("invalid modulus: %w", err)
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, fmt.Errorf("invalid exponent: %w", err)
			}
			if len(eBytes) == 0 {
				return nil, errors.New("empty exponent")
			}

			exp := 0
			for _, b := range eBytes {
				exp = (exp << 8) | int(b)
			}
			if exp == 0 {
				return nil, errors.New("invalid exponent")
			}

			return &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: exp,
			}, nil
		}
	}

	return nil, fmt.Errorf("kid %q not found in apple jwks", kid)
}

func (a *appleAdapter) getJWKS(ctx context.Context) (*appleJWKS, error) {
	ttl := a.jwksTTL
	if ttl <= 0 {
		ttl = defaultAppleJWKSCacheTT
	}

	a.mu.RLock()
	cached := a.jwks
	age := time.Since(a.jwksAt)
	etag := a.jwksETag
	a.mu.RUnlock()

	if cached != nil && age < ttl {
		return cached, nil
	}

	if a.httpClient == nil {
		a.httpClient = sharedSocialHTTPClient()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("jwks request failed: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		if cached == nil {
			return nil, errors.New("jwks not modified but cache empty")
		}
		a.mu.Lock()
		a.jwksAt = time.Now()
		a.mu.Unlock()
		return cached, nil
	case resp.StatusCode/100 != 2:
		if cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("jwks endpoint status %d", resp.StatusCode)
	}

	var fetched appleJWKS
	if err := json.NewDecoder(resp.Body).Decode(&fetched); err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("jwks decode failed: %w", err)
	}
	if len(fetched.Keys) == 0 {
		if cached != nil {
			return cached, nil
		}
		return nil, errors.New("jwks contains no keys")
	}

	a.mu.Lock()
	a.jwks = &fetched
	a.jwksAt = time.Now()
	a.jwksETag = resp.Header.Get("ETag")
	a.mu.Unlock()

	return &fetched, nil
}

func hasAudience(raw any, expected string) bool {
	switch aud := raw.(type) {
	case string:
		return aud == expected
	case []any:
		for _, v := range aud {
			if s, ok := v.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func boolClaim(raw any) bool {
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

func strClaim(claims jwtv5.MapClaims, key string) string {
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}
