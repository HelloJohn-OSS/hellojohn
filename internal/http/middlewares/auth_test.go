package middlewares

import "testing"

func TestIsAcceptedBearerClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{
			name:   "empty claims accepted",
			claims: map[string]any{},
			want:   true,
		},
		{
			name: "refresh token rejected",
			claims: map[string]any{
				"token_use": "refresh",
			},
			want: false,
		},
		{
			name: "session token accepted",
			claims: map[string]any{
				"typ": "session_token",
			},
			want: true,
		},
		{
			name: "access token accepted",
			claims: map[string]any{
				"typ": "access_token",
			},
			want: true,
		},
		{
			name: "unknown typ rejected",
			claims: map[string]any{
				"typ": "id_token",
			},
			want: false,
		},
		{
			name: "typ is optional",
			claims: map[string]any{
				"sub": "user_1",
			},
			want: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isAcceptedBearerClaims(tc.claims)
			if got != tc.want {
				t.Fatalf("got=%v want=%v claims=%v", got, tc.want, tc.claims)
			}
		})
	}
}
