package social

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DiscordFactory implementa ProviderFactory para Discord OAuth.
type DiscordFactory struct {
	TenantProvider TenantProvider
}

func (f *DiscordFactory) Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error) {
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
	if !settings.SocialProviders.DiscordEnabled {
		return nil, fmt.Errorf("discord not enabled for tenant")
	}

	clientID := settings.SocialProviders.DiscordClient
	if clientID == "" {
		return nil, fmt.Errorf("discord client_id not configured")
	}
	clientSecret, err := decryptSecret(settings.SocialProviders.DiscordSecretEnc, "discord")
	if err != nil {
		return nil, err
	}

	redirectURL := fmt.Sprintf("%s/v2/auth/social/discord/callback", strings.TrimRight(baseURL, "/"))
	return &discordAdapter{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		httpClient:   sharedSocialHTTPClient(),
	}, nil
}

type discordAdapter struct {
	clientID, clientSecret, redirectURL string
	httpClient                          *http.Client
}

func (a *discordAdapter) AuthURL(_ context.Context, state, _ string) (string, error) {
	params := url.Values{
		"client_id":     {a.clientID},
		"redirect_uri":  {a.redirectURL},
		"response_type": {"code"},
		"scope":         {"identify email"},
		"state":         {state},
	}
	return "https://discord.com/api/oauth2/authorize?" + params.Encode(), nil
}

func (a *discordAdapter) ExchangeCode(ctx context.Context, code string) (*OIDCTokens, error) {
	data := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {a.redirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://discord.com/api/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("discord token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discord token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discord token exchange: status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("discord token decode: %w", err)
	}

	return &OIDCTokens{
		AccessToken: tok.AccessToken,
		ExpiresIn:   tok.ExpiresIn,
	}, nil
}

// VerifyIDToken for Discord fetches user info from /users/@me.
func (a *discordAdapter) VerifyIDToken(ctx context.Context, idToken, _ string) (*OIDCClaims, error) {
	accessToken := strings.TrimSpace(idToken)
	if accessToken == "" {
		return nil, fmt.Errorf("no access token available")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, fmt.Errorf("discord userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discord userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discord userinfo: status %d", resp.StatusCode)
	}

	var body struct {
		ID            string `json:"id"`
		Username      string `json:"username"`
		GlobalName    string `json:"global_name"`
		Email         string `json:"email"`
		Verified      bool   `json:"verified"`
		Avatar        string `json:"avatar"`
		Discriminator string `json:"discriminator"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("discord userinfo decode: %w", err)
	}

	name := body.GlobalName
	if name == "" {
		name = body.Username
	}

	var avatar string
	if body.Avatar != "" {
		avatar = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", body.ID, body.Avatar)
	}

	return &OIDCClaims{
		Sub:           body.ID,
		Email:         body.Email,
		EmailVerified: body.Verified,
		Name:          name,
		Picture:       avatar,
	}, nil
}
