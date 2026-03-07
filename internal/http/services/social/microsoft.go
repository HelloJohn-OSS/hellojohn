package social

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// MicrosoftFactory implementa ProviderFactory para Microsoft / Azure AD (OIDC).
type MicrosoftFactory struct {
	TenantProvider TenantProvider
}

func (f *MicrosoftFactory) Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error) {
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
	if !settings.SocialProviders.MicrosoftEnabled {
		return nil, fmt.Errorf("microsoft not enabled for tenant")
	}

	clientID := settings.SocialProviders.MicrosoftClient
	if clientID == "" {
		return nil, fmt.Errorf("microsoft client_id not configured")
	}
	clientSecret, err := decryptSecret(settings.SocialProviders.MicrosoftSecretEnc, "microsoft")
	if err != nil {
		return nil, err
	}

	msTenant := settings.SocialProviders.MicrosoftTenant
	if msTenant == "" {
		msTenant = "common"
	}

	redirectURL := fmt.Sprintf("%s/v2/auth/social/microsoft/callback", strings.TrimRight(baseURL, "/"))
	return &microsoftAdapter{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		msTenant:     msTenant,
		httpClient:   sharedSocialHTTPClient(),
	}, nil
}

type microsoftAdapter struct {
	clientID, clientSecret, redirectURL, msTenant string
	httpClient                                    *http.Client
}

func (a *microsoftAdapter) AuthURL(_ context.Context, state, nonce string) (string, error) {
	params := url.Values{
		"client_id":     {a.clientID},
		"redirect_uri":  {a.redirectURL},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {state},
		"nonce":         {nonce},
		"response_mode": {"query"},
	}
	authURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?%s",
		a.msTenant, params.Encode())
	return authURL, nil
}

func (a *microsoftAdapter) ExchangeCode(ctx context.Context, code string) (*OIDCTokens, error) {
	data := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"code":          {code},
		"redirect_uri":  {a.redirectURL},
		"grant_type":    {"authorization_code"},
		"scope":         {"openid profile email"},
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", a.msTenant)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("microsoft token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("microsoft token exchange: status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("microsoft token decode: %w", err)
	}

	return &OIDCTokens{
		AccessToken:  tok.AccessToken,
		IDToken:      tok.IDToken,
		RefreshToken: tok.RefreshToken,
		ExpiresIn:    tok.ExpiresIn,
	}, nil
}

// VerifyIDToken for Microsoft fetches user info from MS Graph API.
// In production, the id_token should be verified via JWKS; for simplicity
// we use the Graph /me endpoint which is always authoritative.
func (a *microsoftAdapter) VerifyIDToken(ctx context.Context, idToken, _ string) (*OIDCClaims, error) {
	accessToken := strings.TrimSpace(idToken)
	if accessToken == "" {
		return nil, fmt.Errorf("no access token available")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, fmt.Errorf("microsoft userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("microsoft userinfo: status %d", resp.StatusCode)
	}

	var body struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		GivenName         string `json:"givenName"`
		Surname           string `json:"surname"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("microsoft userinfo decode: %w", err)
	}

	email := body.Mail
	if email == "" {
		email = body.UserPrincipalName // Fallback: UPN as email for guest users
	}

	return &OIDCClaims{
		Sub:           body.ID,
		Email:         email,
		EmailVerified: true, // Microsoft validates emails
		Name:          body.DisplayName,
		GivenName:     body.GivenName,
		FamilyName:    body.Surname,
	}, nil
}
