package cloud

// ControllerDeps keeps compatibility with server wiring in OSS builds.
type ControllerDeps struct {
	BaseURL string
}

// Controllers is a no-op placeholder for OSS builds.
type Controllers struct{}

// NewControllers returns nil in OSS to disable cloud routes entirely.
func NewControllers(_ any, _ ControllerDeps) *Controllers {
	return nil
}
