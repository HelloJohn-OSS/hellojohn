package admin

// MigrateToIsolatedDBRequest is the request body for migrating a tenant
// from the Global Data Plane to an isolated database.
type MigrateToIsolatedDBRequest struct {
	// DSN is the connection string for the target isolated database.
	DSN string `json:"dsn"`
	// Driver is the database driver (default: "postgres").
	Driver string `json:"driver,omitempty"`
}

// MigrateToIsolatedDBResponse is the response after initiating migration.
type MigrateToIsolatedDBResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	DataCopy string `json:"data_copy,omitempty"` // "required_manual" when data was not copied
}
