package sms

import (
	"context"
	"errors"
	"time"
)

// SMSProvider defines the contract for sending SMS messages.
type SMSProvider interface {
	Send(ctx context.Context, to string, body string) error
}

// Config contains runtime SMS provider settings.
type Config struct {
	Provider string
	Timeout  time.Duration

	TwilioAccountSID string
	TwilioAuthToken  string
	TwilioFrom       string

	VonageAPIKey    string
	VonageAPISecret string
	VonageFrom      string
}

var (
	ErrUnsupportedProvider  = errors.New("unsupported sms provider")
	ErrProviderNotConfigured = errors.New("sms provider not configured")
	ErrSendFailed           = errors.New("sms provider send failed")
)
