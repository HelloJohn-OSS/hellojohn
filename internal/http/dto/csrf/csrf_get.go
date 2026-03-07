package csrf

type GetResponse struct {
	CSRFToken string `json:"csrfToken"`
}
