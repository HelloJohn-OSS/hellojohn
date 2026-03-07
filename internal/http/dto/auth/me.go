package auth

// MeResponse is the response for GET /v2/me.
// Returns selected claims from the access token.
type MeResponse struct {
	Sub    any `json:"sub,omitempty"`
	Tid    any `json:"tid,omitempty"`
	Aud    any `json:"aud,omitempty"`
	Amr    any `json:"amr,omitempty"`
	Custom any `json:"custom,omitempty"`
	Exp    any `json:"exp,omitempty"`
}
