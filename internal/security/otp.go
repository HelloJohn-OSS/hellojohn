package security

import (
	"crypto/rand"
	"math/big"
)

// GenerateOTP crea un código numérico aleatorio y criptográficamente seguro de largo `length`.
// Utiliza crypto/rand para evitar predicciones estadísticas.
func GenerateOTP(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}

	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b[i] = byte('0') + byte(n.Int64())
	}
	return string(b), nil
}

// GenerateOpaqueToken genera un token opaco URL-safe de `n` bytes usando base64url.
func GenerateOpaqueToken(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Encode as URL-safe base64 without padding
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, n)
	for i, v := range b {
		result[i] = alphabet[v%64]
	}
	return string(result), nil
}
