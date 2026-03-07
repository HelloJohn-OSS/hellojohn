package social

// ResultRequest contains the query parameters for GET /v2/auth/social/result.
type ResultRequest struct {
	Code string `json:"code"`
	Peek bool   `json:"peek"` // If true, don't consume the code (debug mode)
}

// ResultResponse is the response for the social result endpoint.
type ResultResponse struct {
	Code       string `json:"code,omitempty"`
	Payload    []byte `json:"-"`           // Raw payload (tokens JSON)
	PayloadB64 string `json:"payload_b64"` // Base64 encoded payload for HTML
	Peek       bool   `json:"peek"`
}
