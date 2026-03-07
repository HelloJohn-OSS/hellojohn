package social

import (
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	sharedSocialHTTPClientOnce sync.Once
	sharedSocialClient         *http.Client
)

func sharedSocialHTTPClient() *http.Client {
	sharedSocialHTTPClientOnce.Do(func() {
		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		sharedSocialClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}
	})
	return sharedSocialClient
}
