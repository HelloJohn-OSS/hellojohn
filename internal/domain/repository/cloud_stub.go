package repository

// CloudUser is intentionally minimal in OSS builds.
type CloudUser struct {
	ID string `json:"id"`
}

// CloudInstance is intentionally minimal in OSS builds.
type CloudInstance struct {
	ID string `json:"id"`
}

// CloudUserRepository is kept for interface compatibility in OSS builds.
type CloudUserRepository interface{}

// CloudInstanceRepository is kept for interface compatibility in OSS builds.
type CloudInstanceRepository interface{}
