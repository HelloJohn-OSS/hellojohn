// Package mcp provides an MCP (Model Context Protocol) server that exposes
// HelloJohn admin operations as tools for AI agents. The server communicates
// with the HelloJohn backend via HTTP using the same API key system as hjctl.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Handler bridges MCP tool calls to the HelloJohn HTTP API.
// It holds the HTTP client configuration (base URL + API key).
type Handler struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewHandler creates a Handler with the given server config.
func NewHandler(baseURL, apiKey string, timeoutSec int) *Handler {
	return &Handler{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

// DoJSON executes an HTTP request against the HelloJohn API.
// It returns the raw JSON response body or an error.
func (h *Handler) DoJSON(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	data, _, err := h.doRequest(ctx, method, path, nil, body)
	return data, err
}

// DoJSONWithHeaders executes an HTTP request with additional custom request headers.
func (h *Handler) DoJSONWithHeaders(ctx context.Context, method, path string, extraHeaders map[string]string, body any) (json.RawMessage, error) {
	data, _, err := h.doRequest(ctx, method, path, extraHeaders, body)
	return data, err
}

// DoJSONGetETag executes a GET request and returns the ETag response header alongside the body.
// The ETag value is returned as-is (including surrounding quotes) for direct use in If-Match.
func (h *Handler) DoJSONGetETag(ctx context.Context, path string) (json.RawMessage, string, error) {
	data, respHeaders, err := h.doRequest(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, "", err
	}
	etag := respHeaders.Get("ETag")
	return data, etag, nil
}

// doRequest is the internal implementation that handles all HTTP requests.
func (h *Handler) doRequest(ctx context.Context, method, path string, extraHeaders map[string]string, body any) (json.RawMessage, http.Header, error) {
	// Serialise body once; we keep the byte slice so each retry can create
	// a fresh *bytes.Reader (an exhausted reader cannot be retried).
	var bodyData []byte
	if body != nil {
		var err error
		bodyData, err = json.Marshal(body)
		if err != nil {
			return nil, nil, fmt.Errorf("encode body: %w", err)
		}
	}

	url := h.BaseURL + path

	var resp *http.Response
	var reqErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}

		// Create a fresh request (and body reader) for every attempt.
		// Reusing the same *http.Request after a failed Do() is unsafe:
		// the body reader may be partially or fully consumed (M-MCP-1).
		var bodyReader io.Reader
		if bodyData != nil {
			bodyReader = bytes.NewReader(bodyData)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return nil, nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		if bodyData != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if h.APIKey != "" {
			req.Header.Set("X-API-Key", h.APIKey)
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}

		resp, reqErr = h.HTTPClient.Do(req)
		if reqErr == nil {
			break
		}
		if !isRetriableNetworkError(reqErr) {
			break
		}
		// Only retry idempotent/safe methods to avoid duplicate mutations.
		if method != http.MethodGet && method != http.MethodHead {
			break
		}
	}
	if reqErr != nil {
		return nil, nil, fmt.Errorf("request failed: %w", reqErr)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		msg := string(respBody)
		if len(msg) > 512 {
			msg = msg[:512] + "... (truncated)"
		}
		return nil, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}

	return json.RawMessage(respBody), resp.Header, nil
}

// isRetriableNetworkError returns true for transient network errors that may succeed on retry.
// Note: "no such host" (NXDOMAIN) is a permanent DNS failure and is NOT retriable.
func isRetriableNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "EOF")
}
