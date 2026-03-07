// Package microsoft implements OAuth 2.0 with Microsoft (Azure AD).
package microsoft

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	authEndpoint  = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	tokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	userInfoURL   = "https://graph.microsoft.com/v1.0/me"
)

// OAuth is the Microsoft OAuth 2.0 client.
type OAuth struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	http         *http.Client
}

// New creates a new Microsoft OAuth client.
func New(clientID, clientSecret, redirectURL string, scopes []string) *OAuth {
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile", "User.Read"}
	}
	return &OAuth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		http:         &http.Client{Timeout: 10 * time.Second},
	}
}

// AuthURL builds the Microsoft authorization URL.
func (m *OAuth) AuthURL(_ context.Context, state, _ string) (string, error) {
	u, _ := url.Parse(authEndpoint)
	q := u.Query()
	q.Set("client_id", m.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", m.RedirectURL)
	q.Set("scope", strings.Join(m.Scopes, " "))
	q.Set("state", state)
	q.Set("response_mode", "query")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// TokenResponse is the response from the Microsoft token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// ExchangeCode exchanges an authorization code for an access token.
func (m *OAuth) ExchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", m.ClientID)
	form.Set("client_secret", m.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", m.RedirectURL)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("microsoft: decode token: %w", err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("microsoft oauth: %s - %s", tr.Error, tr.ErrorDesc)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("microsoft: no access_token in response")
	}
	return &tr, nil
}

// UserInfo contains Microsoft Graph user information.
type UserInfo struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
}

// GetUserInfo retrieves user information from Microsoft Graph.
func (m *OAuth) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("microsoft graph: status %d", resp.StatusCode)
	}

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("microsoft: decode user info: %w", err)
	}

	// Prefer Mail; fallback to UserPrincipalName
	if info.Mail == "" {
		info.Mail = info.UserPrincipalName
	}
	return &info, nil
}
