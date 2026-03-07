package fs

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/security/keycrypto"
	"github.com/dropDatabas3/hellojohn/internal/util/atomicwrite"
)

// keyRepo implementa repository.KeyRepository usando filesystem.
// Compatible con el formato de internal/jwt/keystore_fs_store.go.
type keyRepo struct {
	keysDir string
	mu      sync.RWMutex
	key     string
}

func newKeyRepo(keysDir string, key string) *keyRepo {
	return &keyRepo{keysDir: keysDir, key: key}
}

// keyFileData formato del archivo JSON (compatible con V1 keystore_fs_store.go)
type keyFileData struct {
	KID           string    `json:"kid"`
	Algorithm     string    `json:"algorithm"`
	PrivateKeyEnc string    `json:"private_key_enc"` // Encrypted with SIGNING_MASTER_KEY
	PublicKeyPEM  string    `json:"public_key_pem"`  // PEM encoded public key
	Status        string    `json:"status"`          // "active" or "retiring"
	NotBefore     time.Time `json:"not_before"`
	CreatedAt     time.Time `json:"created_at"`
	// Rotation metadata (only present for retiring.json)
	RetiredAtUnix int64 `json:"retired_at,omitempty"`
	GraceSeconds  int64 `json:"grace_seconds,omitempty"`
}

// dirFor returns the directory for a tenant's keys.
// "" or "global" maps to the base keysDir.
func (r *keyRepo) dirFor(tenantSlug string) string {
	base := filepath.Clean(r.keysDir)
	if tenantSlug == "" || tenantSlug == "global" {
		return base
	}
	return filepath.Join(base, tenantSlug)
}

// ─── Lectura ───

func (r *keyRepo) GetActive(ctx context.Context, tenantSlug string) (*repository.SigningKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dir := r.dirFor(tenantSlug)
	key, err := r.loadKeyFromFile(dir, "active.json")
	if errors.Is(err, fs.ErrNotExist) {
		// Try fallback to global if tenant-specific not found
		if tenantSlug != "" && tenantSlug != "global" {
			return r.loadKeyFromFile(r.dirFor(""), "active.json")
		}
		return nil, repository.ErrNotFound
	}
	return key, err
}

func (r *keyRepo) GetByKID(ctx context.Context, kid string) (*repository.SigningKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Search in all directories (global + tenant subdirs)
	base := filepath.Clean(r.keysDir)

	// Check global active
	if key, err := r.loadKeyFromFile(base, "active.json"); err == nil && key.ID == kid {
		return key, nil
	}
	// Check global retiring
	if key, err := r.loadKeyFromFile(base, "retiring.json"); err == nil && key.ID == kid {
		return key, nil
	}

	// Search tenant subdirs
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("read keys dir: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(base, e.Name())
		if key, err := r.loadKeyFromFile(dir, "active.json"); err == nil && key.ID == kid {
			return key, nil
		}
		if key, err := r.loadKeyFromFile(dir, "retiring.json"); err == nil && key.ID == kid {
			return key, nil
		}
	}

	return nil, repository.ErrNotFound
}

func (r *keyRepo) GetJWKS(ctx context.Context, tenantSlug string) (*repository.JWKS, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dir := r.dirFor(tenantSlug)
	var jwks repository.JWKS

	// Load active
	if key, err := r.loadKeyFromFile(dir, "active.json"); err == nil {
		if jwk, err := r.toJWK(key); err == nil {
			jwks.Keys = append(jwks.Keys, jwk)
		}
	} else if errors.Is(err, fs.ErrNotExist) && tenantSlug != "" && tenantSlug != "global" {
		// Fallback to global
		if key, err := r.loadKeyFromFile(r.dirFor(""), "active.json"); err == nil {
			if jwk, err := r.toJWK(key); err == nil {
				jwks.Keys = append(jwks.Keys, jwk)
			}
		}
		// Add global retiring if exists
		if key, err := r.loadKeyFromFile(r.dirFor(""), "retiring.json"); err == nil {
			if r.isWithinGracePeriod(r.dirFor(""), key) {
				if jwk, err := r.toJWK(key); err == nil {
					jwks.Keys = append(jwks.Keys, jwk)
				}
			}
		}
		return &jwks, nil
	}

	// Load retiring if within grace period
	if key, err := r.loadKeyFromFile(dir, "retiring.json"); err == nil {
		if r.isWithinGracePeriod(dir, key) {
			if jwk, err := r.toJWK(key); err == nil {
				jwks.Keys = append(jwks.Keys, jwk)
			}
		}
	}

	return &jwks, nil
}

func (r *keyRepo) ListAll(ctx context.Context, tenantSlug string) ([]*repository.SigningKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dir := r.dirFor(tenantSlug)
	var keys []*repository.SigningKey

	// Load active key
	if key, err := r.loadKeyFromFile(dir, "active.json"); err == nil {
		key.TenantID = tenantSlug
		keys = append(keys, key)
	} else if errors.Is(err, fs.ErrNotExist) && tenantSlug != "" && tenantSlug != "global" {
		// Fallback to global if tenant-specific not found
		if globalKey, err := r.loadKeyFromFile(r.dirFor(""), "active.json"); err == nil {
			globalKey.TenantID = "" // Mark as global
			keys = append(keys, globalKey)
		}
	}

	// Load retiring key
	if key, err := r.loadKeyFromFile(dir, "retiring.json"); err == nil {
		key.TenantID = tenantSlug
		keys = append(keys, key)
	} else if tenantSlug != "" && tenantSlug != "global" {
		// Check global retiring
		if globalKey, err := r.loadKeyFromFile(r.dirFor(""), "retiring.json"); err == nil {
			globalKey.TenantID = "" // Mark as global
			keys = append(keys, globalKey)
		}
	}

	return keys, nil
}

// ─── Escritura ───

func (r *keyRepo) Generate(ctx context.Context, tenantSlug, algorithm string) (*repository.SigningKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if algorithm == "" {
		algorithm = "EdDSA"
	}

	key, err := r.generateNewKey(algorithm)
	if err != nil {
		return nil, err
	}
	key.TenantID = tenantSlug

	dir := r.dirFor(tenantSlug)
	if err := r.saveKeyToFile(dir, "active.json", key); err != nil {
		return nil, err
	}

	return key, nil
}

func (r *keyRepo) Rotate(ctx context.Context, tenantSlug string, gracePeriod time.Duration) (*repository.SigningKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	dir := r.dirFor(tenantSlug)

	// Read current active
	current, err := r.loadKeyFromFile(dir, "active.json")
	if errors.Is(err, fs.ErrNotExist) {
		// No active key — generate one directly (already holding lock, cannot call Generate)
		newKey, genErr := r.generateNewKey("EdDSA")
		if genErr != nil {
			return nil, fmt.Errorf("generate initial key: %w", genErr)
		}
		newKey.TenantID = tenantSlug
		if saveErr := r.saveKeyToFile(dir, "active.json", newKey); saveErr != nil {
			return nil, fmt.Errorf("save initial key: %w", saveErr)
		}
		return newKey, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load current active: %w", err)
	}

	// Move current to retiring
	graceSeconds := int64(gracePeriod.Seconds())
	if err := r.saveRetiringWithGrace(dir, current, graceSeconds); err != nil {
		return nil, fmt.Errorf("save retiring: %w", err)
	}

	// Generate new active
	newKey, err := r.generateNewKey("EdDSA")
	if err != nil {
		return nil, fmt.Errorf("generate new key: %w", err)
	}
	newKey.TenantID = tenantSlug

	if err := r.saveKeyToFile(dir, "active.json", newKey); err != nil {
		return nil, fmt.Errorf("save new active: %w", err)
	}

	return newKey, nil
}

func (r *keyRepo) Revoke(ctx context.Context, kid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Search for the key by KID and delete it
	base := filepath.Clean(r.keysDir)

	// Check global active
	if key, err := r.loadKeyFromFile(base, "active.json"); err == nil && key.ID == kid {
		path := filepath.Join(base, "active.json")
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove global active key: %w", err)
		}
		return nil
	}

	// Check global retiring
	if key, err := r.loadKeyFromFile(base, "retiring.json"); err == nil && key.ID == kid {
		path := filepath.Join(base, "retiring.json")
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove global retiring key: %w", err)
		}
		return nil
	}

	// Search tenant subdirs
	entries, err := os.ReadDir(base)
	if err != nil {
		return fmt.Errorf("read keys dir: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(base, e.Name())

		// Check tenant active
		if key, err := r.loadKeyFromFile(dir, "active.json"); err == nil && key.ID == kid {
			path := filepath.Join(dir, "active.json")
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove tenant active key: %w", err)
			}
			return nil
		}

		// Check tenant retiring
		if key, err := r.loadKeyFromFile(dir, "retiring.json"); err == nil && key.ID == kid {
			path := filepath.Join(dir, "retiring.json")
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove tenant retiring key: %w", err)
			}
			return nil
		}
	}

	return repository.ErrNotFound
}

// ─── Helpers ───

func (r *keyRepo) ToEdDSA(key *repository.SigningKey) (ed25519.PrivateKey, error) {
	if key.Algorithm != "EdDSA" {
		return nil, fmt.Errorf("key is not EdDSA: %s", key.Algorithm)
	}
	if priv, ok := key.PrivateKey.(ed25519.PrivateKey); ok {
		return priv, nil
	}
	return nil, fmt.Errorf("private key is not ed25519.PrivateKey")
}

func (r *keyRepo) ToECDSA(key *repository.SigningKey) (*ecdsa.PrivateKey, error) {
	if key.Algorithm != "ES256" && key.Algorithm != "ES384" && key.Algorithm != "ES512" {
		return nil, fmt.Errorf("key is not ECDSA: %s", key.Algorithm)
	}
	if priv, ok := key.PrivateKey.(*ecdsa.PrivateKey); ok {
		return priv, nil
	}
	return nil, fmt.Errorf("private key is not *ecdsa.PrivateKey")
}

// ─── Internal helpers ───

func (r *keyRepo) loadKeyFromFile(dir, filename string) (*repository.SigningKey, error) {
	path := filepath.Join(dir, filename)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var kd keyFileData
	if err := json.Unmarshal(data, &kd); err != nil {
		return nil, fmt.Errorf("unmarshal key: %w", err)
	}

	// Decrypt private key if encrypted
	var privateKey any
	if kd.PrivateKeyEnc != "" {
		if r.key == "" {
			return nil, fmt.Errorf("SIGNING_MASTER_KEY not set")
		}
		encrypted, err := base64.StdEncoding.DecodeString(kd.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("decode private key: %w", err)
		}
		decrypted, err := keycrypto.DecryptPrivateKey(encrypted, r.key)
		if err != nil {
			return nil, fmt.Errorf("decrypt private key: %w", err)
		}
		// Parse based on algorithm
		switch kd.Algorithm {
		case "EdDSA":
			privateKey = ed25519.PrivateKey(decrypted)
		default:
			// For ECDSA/RSA, parse from PKCS8
			pk, err := x509.ParsePKCS8PrivateKey(decrypted)
			if err != nil {
				return nil, fmt.Errorf("parse private key: %w", err)
			}
			privateKey = pk
		}
	}

	// Parse public key from PEM - estricto PKIX, sin fallbacks
	block, _ := pem.Decode([]byte(kd.PublicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid public key PEM")
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key PKIX: %w", err)
	}
	var publicKey any
	switch kd.Algorithm {
	case "EdDSA":
		edPub, ok := pk.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not ed25519")
		}
		publicKey = edPub
	default:
		publicKey = pk
	}

	status := repository.KeyStatusActive
	if filename == "retiring.json" || kd.Status == "retiring" {
		status = repository.KeyStatusRetired
	}

	// Enforce NotBefore: reject keys that are not yet valid
	if !kd.NotBefore.IsZero() && time.Now().Before(kd.NotBefore) {
		return nil, fmt.Errorf("key %s is not yet valid (not_before: %s)", kd.KID, kd.NotBefore)
	}

	return &repository.SigningKey{
		ID:         kd.KID,
		TenantID:   "", // Determined by directory
		Algorithm:  kd.Algorithm,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Status:     status,
		CreatedAt:  kd.CreatedAt,
	}, nil
}

func (r *keyRepo) saveKeyToFile(dir, filename string, key *repository.SigningKey) error {
	// masterKey inyectado en construcción via newKeyRepo — nunca leer os.Getenv aquí
	masterKey := r.key
	if masterKey == "" {
		return fmt.Errorf("SIGNING_MASTER_KEY not set: cannot persist key without encryption")
	}

	// Encrypt private key (obligatorio)
	var privateKeyEnc string
	if key.PrivateKey != nil {
		var privBytes []byte
		switch pk := key.PrivateKey.(type) {
		case ed25519.PrivateKey:
			privBytes = pk
		default:
			b, err := x509.MarshalPKCS8PrivateKey(pk)
			if err != nil {
				return fmt.Errorf("marshal private key: %w", err)
			}
			privBytes = b
		}
		encrypted, err := keycrypto.EncryptPrivateKey(privBytes, masterKey)
		if err != nil {
			return fmt.Errorf("encrypt private key: %w", err)
		}
		privateKeyEnc = base64.StdEncoding.EncodeToString(encrypted)
	}

	// Encode public key as PKIX DER in PEM (estándar, sin raw bytes)
	var pubBytes []byte
	switch pk := key.PublicKey.(type) {
	case ed25519.PublicKey:
		b, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return fmt.Errorf("marshal ed25519 public key: %w", err)
		}
		pubBytes = b
	default:
		b, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
		pubBytes = b
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	kd := keyFileData{
		KID:           key.ID,
		Algorithm:     key.Algorithm,
		PrivateKeyEnc: privateKeyEnc,
		PublicKeyPEM:  string(publicKeyPEM),
		Status:        string(key.Status),
		NotBefore:     key.CreatedAt,
		CreatedAt:     key.CreatedAt,
	}

	data, err := json.MarshalIndent(kd, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	// Atomic write using Windows-safe helper
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	finalPath := filepath.Join(dir, filename)
	return atomicwrite.AtomicWriteFile(finalPath, data, 0600)
}

func (r *keyRepo) saveRetiringWithGrace(dir string, key *repository.SigningKey, graceSeconds int64) error {
	// masterKey inyectado en construcción via newKeyRepo — nunca leer os.Getenv aquí
	masterKey := r.key
	if masterKey == "" {
		return fmt.Errorf("SIGNING_MASTER_KEY not set: cannot persist key without encryption")
	}

	var privateKeyEnc string
	if key.PrivateKey != nil {
		var privBytes []byte
		switch pk := key.PrivateKey.(type) {
		case ed25519.PrivateKey:
			privBytes = pk
		default:
			b, err := x509.MarshalPKCS8PrivateKey(pk)
			if err != nil {
				return fmt.Errorf("marshal private key: %w", err)
			}
			privBytes = b
		}
		encrypted, err := keycrypto.EncryptPrivateKey(privBytes, masterKey)
		if err != nil {
			return fmt.Errorf("encrypt private key: %w", err)
		}
		privateKeyEnc = base64.StdEncoding.EncodeToString(encrypted)
	}

	// Encode public key as PKIX DER (estándar)
	var pubBytes []byte
	switch pk := key.PublicKey.(type) {
	case ed25519.PublicKey:
		b, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return fmt.Errorf("marshal ed25519 public key: %w", err)
		}
		pubBytes = b
	default:
		b, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
		pubBytes = b
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	kd := keyFileData{
		KID:           key.ID,
		Algorithm:     key.Algorithm,
		PrivateKeyEnc: privateKeyEnc,
		PublicKeyPEM:  string(publicKeyPEM),
		Status:        "retiring", // Status fijo para retiring.json
		NotBefore:     key.CreatedAt,
		CreatedAt:     key.CreatedAt,
		RetiredAtUnix: time.Now().Unix(),
		GraceSeconds:  graceSeconds,
	}

	data, err := json.MarshalIndent(kd, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	finalPath := filepath.Join(dir, "retiring.json")
	return atomicwrite.AtomicWriteFile(finalPath, data, 0600)
}

func (r *keyRepo) generateNewKey(algorithm string) (*repository.SigningKey, error) {
	now := time.Now().UTC()

	// KID con sufijo random para evitar colisiones si se rota rápido
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("generate random: %w", err)
	}
	kid := "fs-" + now.Format("20060102T150405Z") + "-" + hex.EncodeToString(randomBytes)

	switch algorithm {
	case "EdDSA":
		pub, priv, err := keycrypto.GenerateEd25519()
		if err != nil {
			return nil, fmt.Errorf("generate ed25519: %w", err)
		}
		return &repository.SigningKey{
			ID:         kid,
			Algorithm:  "EdDSA",
			PrivateKey: ed25519.PrivateKey(priv),
			PublicKey:  ed25519.PublicKey(pub),
			Status:     repository.KeyStatusActive, // Status fijo "active"
			CreatedAt:  now,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func (r *keyRepo) isWithinGracePeriod(dir string, key *repository.SigningKey) bool {
	// Read metadata from retiring.json
	path := filepath.Join(dir, "retiring.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return true // Assume within grace if can't read
	}
	var kd keyFileData
	if err := json.Unmarshal(data, &kd); err != nil {
		return true
	}
	if kd.GraceSeconds <= 0 || kd.RetiredAtUnix <= 0 {
		return true // No grace metadata, include it
	}
	expireAt := time.Unix(kd.RetiredAtUnix, 0).Add(time.Duration(kd.GraceSeconds) * time.Second)
	return time.Now().Before(expireAt)
}

func (r *keyRepo) toJWK(key *repository.SigningKey) (repository.JWK, error) {
	switch pk := key.PublicKey.(type) {
	case ed25519.PublicKey:
		return repository.JWK{
			KID: key.ID,
			Kty: "OKP",
			Use: "sig",
			Alg: "EdDSA",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pk),
		}, nil
	case *ecdsa.PublicKey:
		return repository.JWK{
			KID: key.ID,
			Kty: "EC",
			Use: "sig",
			Alg: key.Algorithm,
			Crv: pk.Curve.Params().Name,
			X:   base64.RawURLEncoding.EncodeToString(pk.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pk.Y.Bytes()),
		}, nil
	default:
		return repository.JWK{}, fmt.Errorf("unsupported key type for JWK: %T", pk)
	}
}
