package social

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// FacebookFactory implementa ProviderFactory para Facebook OAuth.
type FacebookFactory struct {
	TenantProvider TenantProvider
}

func (f *FacebookFactory) Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error) {
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
	if !settings.SocialProviders.FacebookEnabled {
		return nil, fmt.Errorf("facebook not enabled for tenant")
	}

	clientID := settings.SocialProviders.FacebookClient
	if clientID == "" {
		return nil, fmt.Errorf("facebook client_id not configured")
	}
	clientSecret, err := decryptSecret(settings.SocialProviders.FacebookSecretEnc, "facebook")
	if err != nil {
		return nil, err
	}

	redirectURL := fmt.Sprintf("%s/v2/auth/social/facebook/callback", strings.TrimRight(baseURL, "/"))
	return &facebookAdapter{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		httpClient:   sharedSocialHTTPClient(),
	}, nil
}

type facebookAdapter struct {
	clientID, clientSecret, redirectURL string
	httpClient                          *http.Client
}

func (a *facebookAdapter) AuthURL(_ context.Context, state, nonce string) (string, error) {
	params := url.Values{
		"client_id":     {a.clientID},
		"redirect_uri":  {a.redirectURL},
		"response_type": {"code"},
		"scope":         {"email,public_profile"},
		"state":         {state},
	}
	return "https://www.facebook.com/v19.0/dialog/oauth?" + params.Encode(), nil
}

func (a *facebookAdapter) ExchangeCode(ctx context.Context, code string) (*OIDCTokens, error) {
	params := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"code":          {code},
		"redirect_uri":  {a.redirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://graph.facebook.com/v19.0/oauth/access_token?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("facebook token request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facebook token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facebook token exchange: status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("facebook token decode: %w", err)
	}

	return &OIDCTokens{
		AccessToken: tok.AccessToken,
		ExpiresIn:   tok.ExpiresIn,
	}, nil
}

// VerifyIDToken for Facebook fetches user info from Graph API.
func (a *facebookAdapter) VerifyIDToken(ctx context.Context, idToken, _ string) (*OIDCClaims, error) {
	accessToken := strings.TrimSpace(idToken)
	if accessToken == "" {
		return nil, fmt.Errorf("no access token available")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://graph.facebook.com/me?fields=id,name,email,picture.type(large)", nil)
	if err != nil {
		return nil, fmt.Errorf("facebook userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facebook userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facebook userinfo: status %d", resp.StatusCode)
	}

	var body struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("facebook userinfo decode: %w", err)
	}

	return &OIDCClaims{
		Sub:           body.ID,
		Email:         body.Email,
		EmailVerified: true, // Facebook validates emails
		Name:          body.Name,
		Picture:       body.Picture.Data.URL,
	}, nil
}
