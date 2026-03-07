package social

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// LinkedInFactory implementa ProviderFactory para LinkedIn (OIDC v2).
type LinkedInFactory struct {
	TenantProvider TenantProvider
}

func (f *LinkedInFactory) Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error) {
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
	if !settings.SocialProviders.LinkedInEnabled {
		return nil, fmt.Errorf("linkedin not enabled for tenant")
	}

	clientID := settings.SocialProviders.LinkedInClient
	if clientID == "" {
		return nil, fmt.Errorf("linkedin client_id not configured")
	}
	clientSecret, err := decryptSecret(settings.SocialProviders.LinkedInSecretEnc, "linkedin")
	if err != nil {
		return nil, err
	}

	redirectURL := fmt.Sprintf("%s/v2/auth/social/linkedin/callback", strings.TrimRight(baseURL, "/"))
	return &linkedinAdapter{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		httpClient:   sharedSocialHTTPClient(),
	}, nil
}

type linkedinAdapter struct {
	clientID, clientSecret, redirectURL string
	httpClient                          *http.Client
}

func (a *linkedinAdapter) AuthURL(_ context.Context, state, _ string) (string, error) {
	params := url.Values{
		"client_id":     {a.clientID},
		"redirect_uri":  {a.redirectURL},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {state},
	}
	return "https://www.linkedin.com/oauth/v2/authorization?" + params.Encode(), nil
}

func (a *linkedinAdapter) ExchangeCode(ctx context.Context, code string) (*OIDCTokens, error) {
	data := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"code":          {code},
		"redirect_uri":  {a.redirectURL},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://www.linkedin.com/oauth/v2/accessToken",
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("linkedin token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("linkedin token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("linkedin token exchange: status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("linkedin token decode: %w", err)
	}

	return &OIDCTokens{
		AccessToken: tok.AccessToken,
		IDToken:     tok.IDToken,
		ExpiresIn:   tok.ExpiresIn,
	}, nil
}

// VerifyIDToken for LinkedIn fetches user info from /v2/userinfo.
func (a *linkedinAdapter) VerifyIDToken(ctx context.Context, idToken, _ string) (*OIDCClaims, error) {
	accessToken := strings.TrimSpace(idToken)
	if accessToken == "" {
		return nil, fmt.Errorf("no access token available")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.linkedin.com/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("linkedin userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("linkedin userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("linkedin userinfo: status %d", resp.StatusCode)
	}

	var body struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("linkedin userinfo decode: %w", err)
	}

	return &OIDCClaims{
		Sub:           body.Sub,
		Email:         body.Email,
		EmailVerified: body.EmailVerified,
		Name:          body.Name,
		GivenName:     body.GivenName,
		FamilyName:    body.FamilyName,
		Picture:       body.Picture,
	}, nil
}
