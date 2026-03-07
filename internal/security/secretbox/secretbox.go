package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	secretBoxEnvVar   = "SECRETBOX_MASTER_KEY"
	nonceSizeGCM      = 12  // AES-GCM nonce size recomendado (96 bits)
	requiredKeyLength = 32  // 32 bytes => AES-256
	sep               = "|" // nonce|ciphertext (ambos en base64)
)

var (
	masterKey     []byte
	masterKeyOnce sync.Once
	loadErr       error
	mu            sync.RWMutex
)

// ensureLoaded carga la clave maestra desde SECRETBOX_MASTER_KEY (base64) una sola vez.
func ensureLoaded() error {
	masterKeyOnce.Do(func() {
		kb64 := strings.TrimSpace(os.Getenv(secretBoxEnvVar))
		if kb64 == "" {
			loadErr = fmt.Errorf("%s no seteada; genere una clave con: openssl rand -base64 32", secretBoxEnvVar)
			return
		}
		k, err := base64.StdEncoding.DecodeString(kb64)
		if err != nil {
			loadErr = fmt.Errorf("decode %s: %w", secretBoxEnvVar, err)
			return
		}
		if len(k) != requiredKeyLength {
			loadErr = fmt.Errorf("%s debe decodificar a %d bytes, obtuvo %d", secretBoxEnvVar, requiredKeyLength, len(k))
			return
		}
		mu.Lock()
		masterKey = make([]byte, len(k))
		copy(masterKey, k)
		mu.Unlock()
	})
	return loadErr
}

// IsSecretBoxReady expone si la clave está cargada (útil para healthchecks/config print).
func IsSecretBoxReady() bool {
	mu.RLock()
	defer mu.RUnlock()
	return len(masterKey) == requiredKeyLength
}

// Encrypt cifra plainText y devuelve base64(nonce)|base64(ciphertext).
func Encrypt(plainText string) (string, error) {
	if err := ensureLoaded(); err != nil {
		return "", err
	}

	mu.RLock()
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	mu.RUnlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, nonceSizeGCM)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce random: %w", err)
	}

	ct := aesgcm.Seal(nil, nonce, []byte(plainText), nil)

	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	ctB64 := base64.StdEncoding.EncodeToString(ct)
	return nonceB64 + sep + ctB64, nil
}

// DecryptWithKey descifra con una clave explícita (base64, hex o raw 32 bytes).
func DecryptWithKey(key string, cipherText string) (string, error) {
	key = strings.TrimSpace(key)
	var kBytes []byte
	decoded := false

	// 1. Intentar Base64 (Std)
	if b, err := base64.StdEncoding.DecodeString(key); err == nil && len(b) == requiredKeyLength {
		kBytes = b
		decoded = true
	}
	// 1.5. Intentar Base64 (Raw/NoPadding)
	if !decoded {
		if b, err := base64.RawStdEncoding.DecodeString(key); err == nil && len(b) == requiredKeyLength {
			kBytes = b
			decoded = true
		}
	}

	// 2. Si no es base64 válido (o no da 32 bytes), intentar Hex
	if !decoded {
		// Chequeo rápido de longitud hex (64 chars = 32 bytes)
		if len(key) == 64 {
			if h, err := hex.DecodeString(key); err == nil && len(h) == requiredKeyLength {
				kBytes = h
				decoded = true
			}
		}
	}

	// 3. Fallback a Raw (si no fue decoded antes)
	if !decoded {
		kBytes = []byte(key)
	}

	if len(kBytes) != requiredKeyLength {
		return "", fmt.Errorf("clave inválida: %d bytes (requiere %d)", len(kBytes), requiredKeyLength)
	}

	parts := strings.Split(cipherText, sep)
	if len(parts) != 2 {
		return "", errors.New("formato inválido: esperado base64(nonce)|base64(ciphertext)")
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	if len(nonce) != nonceSizeGCM {
		return "", fmt.Errorf("nonce inválido: esperado %d bytes, obtuvo %d", nonceSizeGCM, len(nonce))
	}

	block, err := aes.NewCipher(kBytes)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	pt, err := aesgcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("gcm auth/decrypt: %w", err)
	}
	return string(pt), nil
}

// Decrypt recibe base64(nonce)|base64(ciphertext) y devuelve el texto plano.
func Decrypt(cipherText string) (string, error) {
	if err := ensureLoaded(); err != nil {
		return "", err
	}

	parts := strings.Split(cipherText, sep)
	if len(parts) != 2 {
		return "", errors.New("formato inválido: esperado base64(nonce)|base64(ciphertext)")
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	if len(nonce) != nonceSizeGCM {
		return "", fmt.Errorf("nonce inválido: esperado %d bytes, obtuvo %d", nonceSizeGCM, len(nonce))
	}

	mu.RLock()
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	mu.RUnlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	pt, err := aesgcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("gcm auth/decrypt: %w", err)
	}
	return string(pt), nil
}

// --- Helpers para tests ---

// UnsafeResetSecretBoxForTests borra estado interno. Usar sólo en tests.
func UnsafeResetSecretBoxForTests() {
	mu.Lock()
	masterKey = nil
	mu.Unlock()
	masterKeyOnce = sync.Once{}
	loadErr = nil
}

// UnsafeSetMasterKeyForTests permite setear una clave cruda (32 bytes) en tests.
func UnsafeSetMasterKeyForTests(k []byte) error {
	if len(k) != requiredKeyLength {
		return fmt.Errorf("clave inválida para test: se requieren %d bytes", requiredKeyLength)
	}
	UnsafeResetSecretBoxForTests()
	mu.Lock()
	masterKey = make([]byte, len(k))
	copy(masterKey, k)
	mu.Unlock()
	return nil
}
