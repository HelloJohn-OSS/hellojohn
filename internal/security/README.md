# Security Primitives

> Colección de primitivas criptográficas y de seguridad para la aplicación.

## Propósito

Este paquete centraliza todas las operaciones sensibles de seguridad para evitar implementaciones ad-hoc y asegurar el uso de algoritmos robustos y configuraciones seguras.

## Sub-paquetes

### 1. `password` (Argon2id)

Manejo de contraseñas usando **Argon2id**, el estándar ganador de la Password Hashing Competition.

```go
// Hash
hash, err := password.Hash(password.Default, "my-secret-password")

// Verify
match := password.Verify("my-secret-password", hash)
```

-   **Algoritmo**: Argon2id (resistente a GPUs y Side-channels).
-   **Configuración**: Tunable (Memory, Time, Parallelism). Default: 64MB, 3 iterations, 1 thread.

### 2. `secretbox` (AES-GCM)

Cifrado simétrico de propósito general para proteger secretos en reposo (ej: tokens de terceros en DB).
Requiere la variable de entorno `SECRETBOX_MASTER_KEY` (32 bytes base64).

```go
// Encrypt
encrypted, err := secretbox.Encrypt("sensitive-data")
// Output: "base64(nonce)|base64(ciphertext)"

// Decrypt
plaintext, err := secretbox.Decrypt(encrypted)
```

### 3. `keycrypto` (Private Key Protection)

Específico para cifrar claves privadas (Ed25519) usando una Master Key diferente.
Format: `GCMV1` + `nonce` + `ciphertext`.

### 4. `totp` (2FA)

Implementación de Time-Based One-Time Password (RFC 6238).

-   Generación de secretos compatibles con Google Authenticator.
-   Generación de URLs `otpauth://` para códigos QR.
-   Validación con ventanas de tiempo para tolerar desincronización de reloj.

### 5. `token` (Randomness)

Generación de tokens opacos y hashes seguros.
Usa `crypto/rand` exclusivamente.

```go
token, _ := tokens.GenerateOpaqueToken(32) // 32 bytes -> base64url
hash := tokens.SHA256Base64URL(token)
```
