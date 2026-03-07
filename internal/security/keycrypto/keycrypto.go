// Package keycrypto provee funciones de criptografía para manejo de claves de firma.
// Este paquete es neutral y no tiene dependencias de otros paquetes del proyecto.
package keycrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateEd25519 genera un par de claves Ed25519.
func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

// EncryptPrivateKey cifra una clave privada usando AES-GCM con una master key en formato hex.
// El resultado tiene el prefijo "GCMV1" para identificación del formato.
func EncryptPrivateKey(privateKey []byte, masterKeyHex string) ([]byte, error) {
	// Decodificar clave maestra desde hex
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid master key hex: %w", err)
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (64 hex chars), got %d", len(masterKey))
	}

	// Crear cipher AES
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	// Crear GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generar nonce aleatorio
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Cifrar: nonce + ciphertext+tag
	ciphertext := gcm.Seal(nonce, nonce, privateKey, nil)

	// Prefija con magic header para identificación robusta
	result := append([]byte("GCMV1"), ciphertext...)
	return result, nil
}

// DecryptPrivateKey descifra una clave privada usando AES-GCM.
// Espera que el input tenga el prefijo "GCMV1".
func DecryptPrivateKey(encrypted []byte, masterKeyHex string) ([]byte, error) {
	// Verificar magic header
	magicHeader := []byte("GCMV1")
	if len(encrypted) < len(magicHeader) || !bytes.Equal(encrypted[:len(magicHeader)], magicHeader) {
		return nil, fmt.Errorf("invalid encrypted format: missing GCMV1 header")
	}

	// Extraer payload real sin el header
	payload := encrypted[len(magicHeader):]

	// Decodificar clave maestra
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid master key hex: %w", err)
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes")
	}

	// Crear cipher
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extraer nonce y ciphertext del payload
	nonce, ciphertext := payload[:nonceSize], payload[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
