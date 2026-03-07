package sms

import (
	"strings"
	"time"
)

// NewProvider builds the SMS provider configured by driver.
func NewProvider(cfg Config) (SMSProvider, error) {
	driver := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if driver == "" {
		driver = "twilio"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	switch driver {
	case "twilio":
		return newTwilioProvider(cfg)
	case "vonage":
		return newVonageProvider(cfg)
	default:
		return nil, ErrUnsupportedProvider
	}
}
