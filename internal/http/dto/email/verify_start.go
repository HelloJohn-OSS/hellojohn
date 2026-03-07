package email

type VerifyStartRequest struct {
	Email string `json:"email"`
}

type VerifyStartResponse struct {
	OK bool `json:"ok"`
}
