// Package jwt provee utilidades para generación y validación de JWTs.
// Las funciones de criptografía de claves (GenerateEd25519, EncryptPrivateKey, DecryptPrivateKey)
// ahora son wrappers del paquete neutral internal/crypto/keycrypto.
package jwt

import (
	"crypto/ed25519"
	"encoding/base64"

	"github.com/dropDatabas3/hellojohn/internal/security/keycrypto"
)

// GenerateEd25519 genera un par ed25519.
// Wrapper de keycrypto.GenerateEd25519 para compatibilidad.
func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return keycrypto.GenerateEd25519()
}

// EncryptPrivateKey cifra una clave privada usando AES-GCM con una clave maestra.
// Wrapper de keycrypto.EncryptPrivateKey para compatibilidad.
func EncryptPrivateKey(privateKey []byte, masterKeyHex string) ([]byte, error) {
	return keycrypto.EncryptPrivateKey(privateKey, masterKeyHex)
}

// DecryptPrivateKey descifra una clave privada usando AES-GCM.
// Wrapper de keycrypto.DecryptPrivateKey para compatibilidad.
func DecryptPrivateKey(encrypted []byte, masterKeyHex string) ([]byte, error) {
	return keycrypto.DecryptPrivateKey(encrypted, masterKeyHex)
}

// EncodeBase64URL devuelve base64url sin padding.
func EncodeBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeBase64URL decodifica base64url sin padding.
func DecodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
