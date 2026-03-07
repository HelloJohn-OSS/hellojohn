package auth

// CompleteProfileRequest holds the body for POST /v2/auth/complete-profile
type CompleteProfileRequest struct {
	CustomFields map[string]any `json:"custom_fields"`
}

// CompleteProfileResponse is the response for complete profile.
type CompleteProfileResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// CompleteProfileResult is the internal result from CompleteProfileService.
type CompleteProfileResult struct {
	Success bool
	Message string
}
