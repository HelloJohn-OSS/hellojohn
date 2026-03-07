package adaptive

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/cache"
)

// State is the persisted adaptive baseline for a tenant+user.
type State struct {
	LastIP         string
	LastUA         string
	FailedAttempts int
}

func LastIPKey(tenantID, userID string) string {
	return "mfa:adaptive:last_ip:" + strings.TrimSpace(tenantID) + ":" + strings.TrimSpace(userID)
}

func LastUAKey(tenantID, userID string) string {
	return "mfa:adaptive:last_ua:" + strings.TrimSpace(tenantID) + ":" + strings.TrimSpace(userID)
}

func FailKey(tenantID, userID string) string {
	return "mfa:adaptive:fail:" + strings.TrimSpace(tenantID) + ":" + strings.TrimSpace(userID)
}

// LoadState reads adaptive baseline from cache.
func LoadState(ctx context.Context, cacheClient cache.Client, tenantID, userID string) (State, error) {
	if cacheClient == nil {
		return State{}, nil
	}
	lastIP, err := getString(ctx, cacheClient, LastIPKey(tenantID, userID))
	if err != nil {
		return State{}, err
	}
	lastUA, err := getString(ctx, cacheClient, LastUAKey(tenantID, userID))
	if err != nil {
		return State{}, err
	}
	failedAttempts, err := getInt(ctx, cacheClient, FailKey(tenantID, userID))
	if err != nil {
		return State{}, err
	}
	return State{
		LastIP:         lastIP,
		LastUA:         lastUA,
		FailedAttempts: failedAttempts,
	}, nil
}

// SaveSuccessState stores latest successful access baseline and resets failed attempts.
func SaveSuccessState(ctx context.Context, cacheClient cache.Client, tenantID, userID, currentIP, currentUA string, ttl time.Duration) error {
	if cacheClient == nil {
		return nil
	}
	ttl = normalizeTTL(ttl)
	if err := cacheClient.Set(ctx, LastIPKey(tenantID, userID), strings.TrimSpace(currentIP), ttl); err != nil {
		return err
	}
	if err := cacheClient.Set(ctx, LastUAKey(tenantID, userID), strings.TrimSpace(currentUA), ttl); err != nil {
		return err
	}
	return cacheClient.Set(ctx, FailKey(tenantID, userID), "0", ttl)
}

// IncrementFail increases failed attempts counter and returns the updated value.
func IncrementFail(ctx context.Context, cacheClient cache.Client, tenantID, userID string, ttl time.Duration) (int, error) {
	if cacheClient == nil {
		return 0, nil
	}
	ttl = normalizeTTL(ttl)
	current, err := getInt(ctx, cacheClient, FailKey(tenantID, userID))
	if err != nil {
		return 0, err
	}
	current++
	if err := cacheClient.Set(ctx, FailKey(tenantID, userID), strconv.Itoa(current), ttl); err != nil {
		return 0, err
	}
	return current, nil
}

func normalizeTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return DefaultStateTTL
	}
	return ttl
}

func getString(ctx context.Context, cacheClient cache.Client, key string) (string, error) {
	val, err := cacheClient.Get(ctx, key)
	if err != nil {
		if cache.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(val), nil
}

func getInt(ctx context.Context, cacheClient cache.Client, key string) (int, error) {
	raw, err := cacheClient.Get(ctx, key)
	if err != nil {
		if cache.IsNotFound(err) {
			return 0, nil
		}
		return 0, err
	}
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	n, parseErr := strconv.Atoi(strings.TrimSpace(raw))
	if parseErr != nil || n < 0 {
		return 0, nil
	}
	return n, nil
}
