// Package oidc contiene DTOs para endpoints OIDC.
package oidc

// UserInfoResponse representa la respuesta del endpoint /userinfo.
type UserInfoResponse struct {
	Sub           string         `json:"sub"`
	Name          string         `json:"name,omitempty"`
	GivenName     string         `json:"given_name,omitempty"`
	FamilyName    string         `json:"family_name,omitempty"`
	Picture       string         `json:"picture,omitempty"`
	Locale        string         `json:"locale,omitempty"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	CustomFields  map[string]any `json:"custom_fields"`
}
