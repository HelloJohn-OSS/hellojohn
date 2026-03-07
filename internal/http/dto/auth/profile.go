package auth

// ProfileResponse is the response for GET /v2/profile.
// Returns OIDC-style profile claims.
type ProfileResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	UpdatedAt     int64  `json:"updated_at"`
}

// ProfileResult is the internal result from ProfileService.
type ProfileResult struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	UpdatedAt     int64
}
