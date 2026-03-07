package email

type VerifyConfirmRequest struct {
	Token string `json:"token"`
}

type VerifyConfirmResponse struct {
	OK bool `json:"ok"`
}
