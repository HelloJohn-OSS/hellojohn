package oauth

// IntrospectRequest holds the form data for POST /oauth2/introspect.
type IntrospectRequest struct {
	Token      string `json:"token"`
	IncludeSys bool   `json:"include_sys"` // Optional: include roles/perms from system namespace
}

// IntrospectResponse is the response for token introspection (RFC 7662).
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"` // "refresh_token" or "access_token"
	Sub       string `json:"sub,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
	Tid       string `json:"tid,omitempty"`
	Acr       string `json:"acr,omitempty"`
	Amr       any    `json:"amr,omitempty"` // []string or nil
	Roles     any    `json:"roles,omitempty"`
	Perms     any    `json:"perms,omitempty"`
}

// IntrospectResult is the internal result from IntrospectService.
type IntrospectResult struct {
	Active    bool
	TokenType string
	Sub       string
	ClientID  string
	Scope     string
	Exp       int64
	Iat       int64
	Iss       string
	Jti       string
	Tid       string
	Acr       string
	Amr       []string
	Roles     []string
	Perms     []string
}
