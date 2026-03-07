package password

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockRoundTripper permite mockear responses HTTP en tests.
type mockRoundTripper struct {
	statusCode int
	body       string
	err        error
}

func (m *mockRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.body)),
	}, nil
}

func TestBreachDetectionRule_PasswordBreached(t *testing.T) {
	// "password" tiene SHA-1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	// Prefix: 5BAA6, Suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
	//
	// Simulamos que HIBP responde con una lista que contiene el suffix
	suffix := "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
	mockBody := fmt.Sprintf("0018A45C4D1DEF81644B54AB7F969B88D65:1\n%s:3861493\nABC123:5\n", suffix)

	rule := BreachDetectionRule{
		Client: &http.Client{Transport: &mockRoundTripper{statusCode: 200, body: mockBody}},
	}

	v := rule.Validate("password", PolicyContext{})
	if v == nil {
		t.Fatal("expected violation for breached password 'password'")
	}
	if v.Rule != "breach_detection" {
		t.Errorf("expected rule 'breach_detection', got %q", v.Rule)
	}
}

func TestBreachDetectionRule_PasswordSafe(t *testing.T) {
	mockBody := "0018A45C4D1DEF81644B54AB7F969B88D65:1\nABC123:5\n"

	rule := BreachDetectionRule{
		Client: &http.Client{Transport: &mockRoundTripper{statusCode: 200, body: mockBody}},
	}

	v := rule.Validate("xK9!mZq#2rTvW$", PolicyContext{})
	if v != nil {
		t.Errorf("expected no violation for safe password, got: %+v", v)
	}
}

func TestBreachDetectionRule_NetworkFailure_FailOpen(t *testing.T) {
	rule := BreachDetectionRule{
		Client: &http.Client{Transport: &mockRoundTripper{err: fmt.Errorf("network timeout")}},
	}

	v := rule.Validate("anything", PolicyContext{})
	if v != nil {
		t.Errorf("expected nil (fail-open) on network error, got: %+v", v)
	}
}

func TestBreachDetectionRule_BadStatusCode_FailOpen(t *testing.T) {
	rule := BreachDetectionRule{
		Client: &http.Client{Transport: &mockRoundTripper{statusCode: 503, body: ""}},
	}

	v := rule.Validate("anything", PolicyContext{})
	if v != nil {
		t.Errorf("expected nil (fail-open) on 503, got: %+v", v)
	}
}
