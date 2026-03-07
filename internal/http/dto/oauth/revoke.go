package oauth

// RevokeRequest holds the body for POST /oauth2/revoke.
// Token can come from form, Bearer header, or JSON body.
type RevokeRequest struct {
	Token string `json:"token"`
}

// RevokeResponse is the response for token revocation.
// Always returns empty 200 OK per RFC 7009 (idempotent).
type RevokeResponse struct{}
