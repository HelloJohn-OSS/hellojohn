package session

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
)

type fakeSessionCache struct {
	data        map[string][]byte
	deletedKeys []string
}

func newFakeSessionCache() *fakeSessionCache {
	return &fakeSessionCache{data: make(map[string][]byte)}
}

func (f *fakeSessionCache) Get(key string) ([]byte, bool) {
	v, ok := f.data[key]
	return v, ok
}

func (f *fakeSessionCache) Set(key string, value []byte, ttl time.Duration) error {
	f.data[key] = value
	return nil
}

func (f *fakeSessionCache) Delete(key string) error {
	f.deletedKeys = append(f.deletedKeys, key)
	delete(f.data, key)
	return nil
}

type fakeSessionTokenIssuer struct {
	lastSub      string
	lastTenantID string
	lastTTL      time.Duration
	token        string
	exp          time.Time
	err          error
}

func (f *fakeSessionTokenIssuer) MintSessionToken(sub, tenantID string, ttl time.Duration) (string, time.Time, error) {
	f.lastSub = sub
	f.lastTenantID = tenantID
	f.lastTTL = ttl
	if f.err != nil {
		return "", time.Time{}, f.err
	}
	return f.token, f.exp, nil
}

func TestSessionTokenServiceMintFromSession(t *testing.T) {
	t.Parallel()

	const rawSession = "session_123"
	cacheKey := "sid:" + tokens.SHA256Base64URL(rawSession)

	basePayload := dto.SessionPayload{
		UserID:   "user_1",
		TenantID: "tenant_1",
		Expires:  time.Now().Add(10 * time.Minute),
	}
	basePayloadJSON, _ := json.Marshal(basePayload)

	tests := []struct {
		name        string
		sessionID   string
		cacheData   map[string][]byte
		issuerErr   error
		wantErr     error
		wantDeleted bool
	}{
		{
			name:      "missing session id",
			sessionID: "",
			wantErr:   ErrSessionTokenMissingSession,
		},
		{
			name:      "session not found",
			sessionID: rawSession,
			cacheData: map[string][]byte{},
			wantErr:   ErrSessionTokenNotFound,
		},
		{
			name:      "invalid payload",
			sessionID: rawSession,
			cacheData: map[string][]byte{
				cacheKey: []byte("{invalid-json"),
			},
			wantErr:     ErrSessionTokenInvalidSession,
			wantDeleted: true,
		},
		{
			name:      "expired payload",
			sessionID: rawSession,
			cacheData: map[string][]byte{
				cacheKey: mustJSON(t, dto.SessionPayload{
					UserID:   "user_1",
					TenantID: "tenant_1",
					Expires:  time.Now().Add(-1 * time.Minute),
				}),
			},
			wantErr:     ErrSessionTokenExpired,
			wantDeleted: true,
		},
		{
			name:      "issuer failure",
			sessionID: rawSession,
			cacheData: map[string][]byte{
				cacheKey: basePayloadJSON,
			},
			issuerErr: errors.New("sign fail"),
			wantErr:   ErrSessionTokenMintFailed,
		},
		{
			name:      "success",
			sessionID: rawSession,
			cacheData: map[string][]byte{
				cacheKey: basePayloadJSON,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cache := newFakeSessionCache()
			for k, v := range tc.cacheData {
				cache.data[k] = v
			}

			issuer := &fakeSessionTokenIssuer{
				token: "jwt_session_token",
				exp:   time.Now().Add(5 * time.Minute),
				err:   tc.issuerErr,
			}

			svc := NewSessionTokenService(SessionTokenDeps{
				Cache:    cache,
				Issuer:   issuer,
				TokenTTL: 5 * time.Minute,
			})

			result, err := svc.MintFromSession(context.Background(), tc.sessionID)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				if tc.wantDeleted && len(cache.deletedKeys) == 0 {
					t.Fatalf("expected session deletion side effect")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil || result.Token == "" || result.ExpiresIn <= 0 {
				t.Fatalf("invalid result: %+v", result)
			}

			if issuer.lastSub != basePayload.UserID {
				t.Fatalf("issuer sub mismatch: got=%q want=%q", issuer.lastSub, basePayload.UserID)
			}
			if issuer.lastTenantID != basePayload.TenantID {
				t.Fatalf("issuer tenant mismatch: got=%q want=%q", issuer.lastTenantID, basePayload.TenantID)
			}
			if issuer.lastTTL != 5*time.Minute {
				t.Fatalf("issuer ttl mismatch: got=%v", issuer.lastTTL)
			}

			if tc.wantDeleted && len(cache.deletedKeys) == 0 {
				t.Fatalf("expected session deletion side effect")
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	return b
}
