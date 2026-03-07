package cloud

// ProxyService is intentionally opaque in OSS builds.
type ProxyService interface{}

// Services is a no-op placeholder for OSS builds.
type Services struct {
	Proxy          ProxyService
	CloudInstances any
}

// Deps keeps wiring compatibility while cloud functionality stays disabled.
type Deps struct {
	ConfigAccess          any
	Issuer                any
	CloudOIDCIssuer       string
	CloudOIDCClientID     string
	CloudOIDCClientSecret string
	CloudOIDCRedirectURI  string
	AllowInsecure         bool
	BaseURL               string
	ProxyRateLimitRead    int
	ProxyRateLimitWrite   int
	AuditBus              any
}

// New returns nil in OSS to guarantee cloud services are disabled.
func New(_ Deps) *Services {
	return nil
}
