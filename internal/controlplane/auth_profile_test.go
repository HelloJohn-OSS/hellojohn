package controlplane

import (
	"reflect"
	"testing"
)

func TestNormalizeAuthProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "default spa when empty", input: "", want: AuthProfileSPA},
		{name: "normalize casing", input: "Web_SSR", want: AuthProfileWebSSR},
		{name: "native", input: "native", want: AuthProfileNative},
		{name: "m2m", input: "m2m", want: AuthProfileM2M},
		{name: "invalid", input: "desktop", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeAuthProfile(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for profile %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("profile mismatch: got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestCoerceGrantTypesForProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile string
		input   []string
		want    []string
	}{
		{
			name:    "m2m forces client credentials",
			profile: AuthProfileM2M,
			input:   []string{"authorization_code", "client_credentials"},
			want:    []string{"client_credentials"},
		},
		{
			name:    "spa forces auth code and refresh without client creds",
			profile: AuthProfileSPA,
			input:   []string{"client_credentials"},
			want:    []string{"authorization_code", "refresh_token"},
		},
		{
			name:    "web_ssr keeps explicit valid grants and required defaults",
			profile: AuthProfileWebSSR,
			input:   []string{"client_credentials"},
			want:    []string{"authorization_code", "refresh_token", "client_credentials"},
		},
		{
			name:    "web_ssr default grants when empty",
			profile: AuthProfileWebSSR,
			input:   nil,
			want:    []string{"authorization_code", "refresh_token", "client_credentials"},
		},
		{
			name:    "native forces auth code and refresh",
			profile: AuthProfileNative,
			input:   []string{"authorization_code"},
			want:    []string{"authorization_code", "refresh_token"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := CoerceGrantTypesForProfile(tc.profile, tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("grant types mismatch: got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestValidateGrant(t *testing.T) {
	t.Parallel()

	if ValidateGrant(AuthProfileM2M, "authorization_code") {
		t.Fatalf("m2m must not allow authorization_code")
	}
	if !ValidateGrant(AuthProfileM2M, "client_credentials") {
		t.Fatalf("m2m must allow client_credentials")
	}
	if !ValidateGrant(AuthProfileSPA, "refresh_token") {
		t.Fatalf("spa must allow refresh_token")
	}
}
