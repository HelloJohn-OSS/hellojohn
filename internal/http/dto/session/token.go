package session

// SessionTokenResponse is the response for POST /v2/session/token.
type SessionTokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}
