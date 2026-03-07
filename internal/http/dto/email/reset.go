package email

type ResetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type ResetResponse struct {
	OK bool `json:"ok"`
}
