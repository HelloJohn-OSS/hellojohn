// Package github implements OAuth 2.0 authentication with GitHub.
// Unlike Google OIDC, GitHub uses OAuth 2.0 without ID tokens,
// requiring a separate API call to fetch user information.
package github

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
	authEndpoint  = "https://github.com/login/oauth/authorize"
	tokenEndpoint = "https://github.com/login/oauth/access_token"
	userEndpoint  = "https://api.github.com/user"
	emailEndpoint = "https://api.github.com/user/emails"
)

// OAuth is the GitHub OAuth 2.0 client.
type OAuth struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	http *http.Client
}

// New creates a new GitHub OAuth client.
func New(clientID, clientSecret, redirectURL string, scopes []string) *OAuth {
	if len(scopes) == 0 {
		scopes = []string{"user:email", "read:user"}
	}
	return &OAuth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		http:         &http.Client{Timeout: 10 * time.Second},
	}
}

// AuthURL builds the authorization URL for GitHub OAuth.
func (g *OAuth) AuthURL(ctx context.Context, state, nonce string) (string, error) {
	u, _ := url.Parse(authEndpoint)
	q := u.Query()
	q.Set("client_id", g.ClientID)
	q.Set("redirect_uri", g.RedirectURL)
	q.Set("scope", strings.Join(g.Scopes, " "))
	q.Set("state", state)
	// GitHub doesn't support nonce directly, but we can include it in state
	// The nonce is already encoded in our JWT state token
	q.Set("allow_signup", "true")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// TokenResponse is the response from GitHub's token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// ExchangeCode exchanges an authorization code for an access token.
func (g *OAuth) ExchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", g.ClientID)
	form.Set("client_secret", g.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", g.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if tr.Error != "" {
		return nil, fmt.Errorf("github oauth error: %s - %s", tr.Error, tr.ErrorDesc)
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in response")
	}

	return &tr, nil
}

// UserInfo contains user information from GitHub API.
type UserInfo struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
	Type      string `json:"type"`
	Bio       string `json:"bio"`
	Location  string `json:"location"`
	Company   string `json:"company"`
}

// EmailInfo contains email information from GitHub API.
type EmailInfo struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// GetUserInfo fetches user information using the access token.
func (g *OAuth) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", userEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api error: status %d", resp.StatusCode)
	}

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &info, nil
}

// GetPrimaryEmail fetches the user's primary verified email.
// This is needed because some GitHub users have private emails.
func (g *OAuth) GetPrimaryEmail(ctx context.Context, accessToken string) (*EmailInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", emailEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api error: status %d", resp.StatusCode)
	}

	var emails []EmailInfo
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return nil, fmt.Errorf("failed to decode emails: %w", err)
	}

	// Find primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return &e, nil
		}
	}

	// Fallback to any verified email
	for _, e := range emails {
		if e.Verified {
			return &e, nil
		}
	}

	// Fallback to any email
	if len(emails) > 0 {
		return &emails[0], nil
	}

	return nil, fmt.Errorf("no email found")
}

// GetUserWithEmail fetches user info and ensures we have an email.
// GitHub sometimes returns empty email in user info, so we fetch from /user/emails.
func (g *OAuth) GetUserWithEmail(ctx context.Context, accessToken string) (*UserInfo, error) {
	info, err := g.GetUserInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	// If email is empty, fetch from emails API
	if info.Email == "" {
		emailInfo, err := g.GetPrimaryEmail(ctx, accessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to get email: %w", err)
		}
		info.Email = emailInfo.Email
	}

	return info, nil
}
