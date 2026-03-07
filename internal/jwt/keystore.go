// Package jwt provee utilidades para firma y validación de JWT.
package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

var (
	ErrNoActiveKey = errors.New("no_active_signing_key")
)

// PersistentKeystore wrappea repository.KeyRepository con caching local.
// Provee métodos de conveniencia para firmar (Active/ActiveForTenant) y
// verificar (PublicKeyByKID/PublicKeyByKIDForTenant) tokens.
type PersistentKeystore struct {
	repo repository.KeyRepository

	mu         sync.RWMutex
	activeKID  string
	activePriv ed25519.PrivateKey
	activePub  ed25519.PublicKey
	cacheUntil time.Time
	cacheTTL   time.Duration

	// JWKS cache
	lastJWKS  []byte
	jwksUntil time.Time
	jwksTTL   time.Duration
}

// NewPersistentKeystore crea un nuevo keystore usando un KeyRepository.
func NewPersistentKeystore(repo repository.KeyRepository) *PersistentKeystore {
	return &PersistentKeystore{
		repo:     repo,
		cacheTTL: 30 * time.Second,
		jwksTTL:  15 * time.Second,
	}
}

// EnsureBootstrap genera una clave si no existe ninguna.
func (k *PersistentKeystore) EnsureBootstrap(ctx context.Context) error {
	_, err := k.repo.GetActive(ctx, "")
	if err == nil {
		return nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	// Generar clave inicial
	_, err = k.repo.Generate(ctx, "", "EdDSA")
	return err
}

// Active devuelve la clave activa global (cacheada).
func (k *PersistentKeystore) Active() (kid string, priv ed25519.PrivateKey, pub ed25519.PublicKey, err error) {
	return k.ActiveForTenant("")
}

// ActiveForTenant devuelve la clave activa para un tenant (o global si tenant="").
func (k *PersistentKeystore) ActiveForTenant(tenant string) (kid string, priv ed25519.PrivateKey, pub ed25519.PublicKey, err error) {
	// Para simplificar, no cacheamos por tenant; solo global
	if tenant == "" {
		k.mu.RLock()
		if time.Now().Before(k.cacheUntil) && k.activeKID != "" && len(k.activePriv) > 0 {
			defer k.mu.RUnlock()
			return k.activeKID, k.activePriv, k.activePub, nil
		}
		k.mu.RUnlock()
	}

	ctx := context.Background()
	key, err := k.repo.GetActive(ctx, tenant)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", nil, nil, ErrNoActiveKey
		}
		return "", nil, nil, err
	}

	priv, err = k.repo.ToEdDSA(key)
	if err != nil {
		return "", nil, nil, err
	}
	pub = priv.Public().(ed25519.PublicKey)

	// Cachear solo si es global
	if tenant == "" {
		k.mu.Lock()
		k.activeKID = key.ID
		k.activePriv = priv
		k.activePub = pub
		k.cacheUntil = time.Now().Add(k.cacheTTL)
		k.mu.Unlock()
	}

	return key.ID, priv, pub, nil
}

// PublicKeyByKID devuelve la pubkey por KID (global).
func (k *PersistentKeystore) PublicKeyByKID(kid string) (ed25519.PublicKey, error) {
	return k.PublicKeyByKIDForTenant("", kid)
}

// PublicKeyByKIDForTenant devuelve la pubkey por KID dentro del ámbito de un tenant.
func (k *PersistentKeystore) PublicKeyByKIDForTenant(tenant, kid string) (ed25519.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("kid_missing")
	}

	// Primero chequeamos cache global
	k.mu.RLock()
	if kid == k.activeKID && len(k.activePub) > 0 {
		pub := make([]byte, len(k.activePub))
		copy(pub, k.activePub)
		k.mu.RUnlock()
		return ed25519.PublicKey(pub), nil
	}
	k.mu.RUnlock()

	// Buscar en JWKS del tenant
	ctx := context.Background()
	jwks, err := k.repo.GetJWKS(ctx, tenant)
	if err != nil {
		return nil, err
	}

	for _, jk := range jwks.Keys {
		if jk.KID == kid {
			// Decodificar X (base64url) a ed25519.PublicKey
			xBytes, err := DecodeBase64URL(jk.X)
			if err != nil {
				return nil, err
			}
			return ed25519.PublicKey(xBytes), nil
		}
	}

	return nil, errors.New("kid_not_found")
}

// JWKSJSON construye el JWKS JSON global (cacheado).
func (k *PersistentKeystore) JWKSJSON() ([]byte, error) {
	return k.JWKSJSONForTenant("")
}

// JWKSJSONForTenant construye el JWKS JSON para un tenant específico.
func (k *PersistentKeystore) JWKSJSONForTenant(tenant string) ([]byte, error) {
	// Cache solo para global
	if tenant == "" {
		k.mu.RLock()
		if time.Now().Before(k.jwksUntil) && len(k.lastJWKS) > 0 {
			defer k.mu.RUnlock()
			return k.lastJWKS, nil
		}
		k.mu.RUnlock()
	}

	ctx := context.Background()
	jwks, err := k.repo.GetJWKS(ctx, tenant)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(jwks)
	if err != nil {
		return nil, err
	}

	// Cachear solo global
	if tenant == "" {
		k.mu.Lock()
		k.lastJWKS = data
		k.jwksUntil = time.Now().Add(k.jwksTTL)
		k.mu.Unlock()
	}

	return data, nil
}

// RotateFor rota las claves de un tenant.
func (k *PersistentKeystore) RotateFor(tenant string, graceSeconds int64) (*repository.SigningKey, error) {
	ctx := context.Background()
	gracePeriod := time.Duration(graceSeconds) * time.Second
	return k.repo.Rotate(ctx, tenant, gracePeriod)
}
