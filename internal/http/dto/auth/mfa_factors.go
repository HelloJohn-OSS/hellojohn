// Package auth contains DTOs for MFA factors endpoints.
package auth

// MFAFactorsResponse is the response for GET /v2/mfa/factors.
type MFAFactorsResponse struct {
	AvailableFactors []string `json:"available_factors"`
	PreferredFactor  string   `json:"preferred_factor,omitempty"`
}

// UpdateMFAFactorPreferenceRequest is the request for PUT /v2/mfa/factors/preference.
type UpdateMFAFactorPreferenceRequest struct {
	Factor string `json:"factor"`
}

// UpdateMFAFactorPreferenceResponse is the response for PUT /v2/mfa/factors/preference.
type UpdateMFAFactorPreferenceResponse struct {
	Updated         bool   `json:"updated"`
	PreferredFactor string `json:"preferred_factor"`
}
