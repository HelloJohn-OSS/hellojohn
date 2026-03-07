package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the HTTP client wrapper for hjctl.
// Automatically adds X-API-Key header and parses error responses.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// ErrorResponse is the standard error format from the HelloJohn API.
type ErrorResponse struct {
	Error  string `json:"error"`
	Code   string `json:"code,omitempty"`
	Status int    `json:"status,omitempty"`
}

func (e *ErrorResponse) String() string {
	if e.Code != "" {
		return fmt.Sprintf("%s (code: %s, status: %d)", e.Error, e.Code, e.Status)
	}
	return e.Error
}

// APIError represents an HTTP error response from the HelloJohn API.
type APIError struct {
	Status  int
	Message string
	Code    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("HTTP %d: %s (code: %s)", e.Status, e.Message, e.Code)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
}

// New creates a new Client with the given configuration.
func New(baseURL, apiKey string, timeoutSec int) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

// isRetriableClientError returns true for transient network errors on
// idempotent methods (GET/HEAD). Does not retry on DNS resolution failures.
func isRetriableClientError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Exclude permanent failures: no such host, connection refused, TLS errors.
	for _, perm := range []string{"no such host", "connection refused", "certificate"} {
		if strings.Contains(msg, perm) {
			return false
		}
	}
	// Retry on generic network errors: EOF, broken pipe, timeout.
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(msg, "EOF") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "reset by peer")
}

// Do executes an HTTP request and decodes the response into `out`.
// GET and HEAD requests are retried up to 3 times on transient network errors.
// If status >= 400, returns a typed error with the server's message.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	const maxRetries = 3
	isIdempotent := method == http.MethodGet || method == http.MethodHead

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 300 * time.Millisecond):
			}
		}

		var bodyReader io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("encode body: %w", err)
			}
			bodyReader = bytes.NewReader(data)
		}

		url := c.BaseURL + path
		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.APIKey != "" {
			req.Header.Set("X-API-Key", c.APIKey)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			if isIdempotent && isRetriableClientError(err) {
				continue
			}
			return lastErr
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("read response: %w", err)
		}

		if resp.StatusCode >= 400 {
			var errResp ErrorResponse
			if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
				return &APIError{
					Status:  resp.StatusCode,
					Message: errResp.Error,
					Code:    errResp.Code,
				}
			}
			return &APIError{Status: resp.StatusCode, Message: string(respBody)}
		}

		if out != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
		}

		return nil
	}

	return lastErr
}

// Get is a convenience method for GET requests.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

// Post is a convenience method for POST requests.
func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	return c.Do(ctx, http.MethodPost, path, body, out)
}

// PostWithBearer executes a POST request using a Bearer token for authorisation
// instead of the X-API-Key header. Used during the email/password bootstrap
// flow in 'auth login' (step 2: create first API key via JWT).
func (c *Client) PostWithBearer(ctx context.Context, path, bearerToken string, body, out any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return &APIError{Status: resp.StatusCode, Message: errResp.Error, Code: errResp.Code}
		}
		return &APIError{Status: resp.StatusCode, Message: string(respBody)}
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Put is a convenience method for PUT requests.
func (c *Client) Put(ctx context.Context, path string, body, out any) error {
	return c.Do(ctx, http.MethodPut, path, body, out)
}

// Delete is a convenience method for DELETE requests.
func (c *Client) Delete(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodDelete, path, nil, out)
}
