package admin

// CreateInvitationRequest body para crear invitaciones.
type CreateInvitationRequest struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// InvitationResponse representa una invitacion en API.
type InvitationResponse struct {
	ID         string   `json:"id"`
	Email      string   `json:"email"`
	Status     string   `json:"status"`
	Roles      []string `json:"roles"`
	ExpiresAt  string   `json:"expires_at"`
	AcceptedAt *string  `json:"accepted_at,omitempty"`
	CreatedAt  string   `json:"created_at"`
}

// ListInvitationsResponse representa listado paginado de invitaciones.
type ListInvitationsResponse struct {
	Invitations []InvitationResponse `json:"invitations"`
	Total       int                  `json:"total"`
	Limit       int                  `json:"limit"`
	Offset      int                  `json:"offset"`
}

// AcceptInvitationRequest body para aceptar invitacion.
type AcceptInvitationRequest struct {
	Token     string `json:"token"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// AcceptInvitationResponse respuesta al aceptar invitacion.
type AcceptInvitationResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

