package commands

import (
	"testing"
)

func TestPickTunnelSettingPrecedence(t *testing.T) {
	tests := []struct {
		name      string
		primary   string
		secondary string
		fallback  string
		want      string
	}{
		{
			name:      "uses primary when set",
			primary:   "flag",
			secondary: "profile",
			fallback:  "env",
			want:      "flag",
		},
		{
			name:      "uses secondary when primary empty",
			primary:   "",
			secondary: "profile",
			fallback:  "env",
			want:      "profile",
		},
		{
			name:      "uses fallback when others empty",
			primary:   "",
			secondary: "",
			fallback:  "env",
			want:      "env",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pickTunnelSetting(tc.primary, tc.secondary, tc.fallback)
			if got != tc.want {
				t.Fatalf("pickTunnelSetting() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTunnelTokenPrefix(t *testing.T) {
	short := "hjtun_short"
	if got := tunnelTokenPrefix(short); got != short {
		t.Fatalf("tunnelTokenPrefix(short) = %q, want %q", got, short)
	}

	long := "hjtun_abcdefghijklmnopqrstuvwxyz"
	if got := tunnelTokenPrefix(long); got != "hjtun_abcdef" {
		t.Fatalf("tunnelTokenPrefix(long) = %q, want %q", got, "hjtun_abcdef")
	}
}

func TestResolveServerBaseURL(t *testing.T) {
	baseURL, port, err := resolveServerBaseURL(map[string]string{
		"BASE_URL": "http://localhost:8080",
	}, 9090)
	if err != nil {
		t.Fatalf("resolveServerBaseURL() error = %v", err)
	}
	if baseURL != "http://localhost:9090" {
		t.Fatalf("baseURL = %q, want %q", baseURL, "http://localhost:9090")
	}
	if port != 9090 {
		t.Fatalf("port = %d, want %d", port, 9090)
	}
}
