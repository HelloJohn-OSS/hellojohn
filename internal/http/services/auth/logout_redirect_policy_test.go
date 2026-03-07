package auth

import "testing"

func TestNormalizePostLogoutRedirectURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{
			name:  "normalizes host casing and empty path",
			input: "https://APP.Example.com",
			want:  "https://app.example.com/",
			ok:    true,
		},
		{
			name:  "drops default https port",
			input: "https://app.example.com:443/callback",
			want:  "https://app.example.com/callback",
			ok:    true,
		},
		{
			name:  "drops default http port",
			input: "http://127.0.0.1:80/callback?x=1",
			want:  "http://127.0.0.1/callback?x=1",
			ok:    true,
		},
		{
			name:  "rejects non http scheme",
			input: "javascript:alert(1)",
			ok:    false,
		},
		{
			name:  "rejects relative uri",
			input: "/logout",
			ok:    false,
		},
		{
			name:  "rejects fragment",
			input: "https://app.example.com/callback#frag",
			ok:    false,
		},
		{
			name:  "rejects userinfo",
			input: "https://user@app.example.com/callback",
			ok:    false,
		},
		{
			name:  "keeps custom port and ipv6 host",
			input: "https://[::1]:4443/callback",
			want:  "https://[::1]:4443/callback",
			ok:    true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := normalizePostLogoutRedirectURI(tc.input)
			if ok != tc.ok {
				t.Fatalf("ok mismatch: got=%v want=%v output=%q", ok, tc.ok, got)
			}
			if !tc.ok {
				return
			}
			if got != tc.want {
				t.Fatalf("normalized URI mismatch: got=%q want=%q", got, tc.want)
			}
		})
	}
}
