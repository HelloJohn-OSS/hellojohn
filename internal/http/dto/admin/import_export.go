package admin

// UserImportRecord representa un usuario dentro del payload de import.
type UserImportRecord struct {
	Email         string                 `json:"email"`
	Name          string                 `json:"name"`
	PasswordHash  string                 `json:"password_hash"`
	HashAlgorithm string                 `json:"hash_algorithm"`
	EmailVerified bool                   `json:"email_verified"`
	Disabled      bool                   `json:"disabled"`
	Roles         []string               `json:"roles"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// StartUserImportResponse es la respuesta inmediata al iniciar un import.
type StartUserImportResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

// UserImportStatusResponse es el estado de un job de import.
type UserImportStatusResponse struct {
	JobID     string                  `json:"job_id"`
	Status    string                  `json:"status"`
	Total     int                     `json:"total"`
	Created   int                     `json:"created"`
	Failed    int                     `json:"failed"`
	ErrorLog  []UserImportStatusError `json:"error_log,omitempty"`
	CreatedAt string                  `json:"created_at"`
	UpdatedAt string                  `json:"updated_at"`
}

// UserImportStatusError describe un error por registro de import.
type UserImportStatusError struct {
	Line  int    `json:"line"`
	Email string `json:"email,omitempty"`
	Error string `json:"error"`
}

// UserExportRecord es la representación de usuario exportado.
// Nunca incluye password_hash.
type UserExportRecord struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	Name          string                 `json:"name"`
	EmailVerified bool                   `json:"email_verified"`
	Disabled      bool                   `json:"disabled"`
	CreatedAt     string                 `json:"created_at"`
	CustomFields  map[string]interface{} `json:"custom_fields,omitempty"`
}
