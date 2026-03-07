package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parámetros tunables para Argon2id.
type Params struct {
	Memory      uint32 // KiB
	Time        uint32
	Parallelism uint8
	KeyLen      uint32
}

// Valores por defecto: fuertes pero razonables para server.
var Default = Params{
	Memory:      64 * 1024, // 64 MiB
	Time:        3,
	Parallelism: 1,
	KeyLen:      32,
}

// Hash devuelve un PHC string del estilo:
// $argon2id$v=19$m=<mem>,t=<time>,p=<par>$<saltB64>$<dkB64>
func Hash(p Params, plain string) (string, error) {
	if plain == "" {
		return "", fmt.Errorf("empty password")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := argon2.IDKey([]byte(plain), salt, p.Time, p.Memory, p.Parallelism, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.Memory, p.Time, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

// decodeB64 intenta std y url-safe sin padding.
func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// Verify valida un PHC string generado por Hash contra la contraseña en claro.
func Verify(plain, phc string) bool {
	if plain == "" || phc == "" {
		return false
	}
	// Formato PHC esperado:
	// $argon2id$v=19$m=65536,t=3,p=1$<saltB64>$<dkB64>
	parts := strings.Split(phc, "$")
	if len(parts) < 6 || parts[1] != "argon2id" {
		return false
	}
	// version
	if !strings.HasPrefix(parts[2], "v=") {
		return false
	}
	v, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || v != 19 {
		return false
	}
	// params
	params := parts[3]
	var m, t, p int
	for _, kv := range strings.Split(params, ",") {
		kvp := strings.SplitN(kv, "=", 2)
		if len(kvp) != 2 {
			continue
		}
		switch kvp[0] {
		case "m":
			m, _ = strconv.Atoi(kvp[1])
		case "t":
			t, _ = strconv.Atoi(kvp[1])
		case "p":
			p, _ = strconv.Atoi(kvp[1])
		}
	}
	if m <= 0 || t <= 0 || p <= 0 {
		return false
	}
	salt, err := decodeB64(parts[4])
	if err != nil {
		return false
	}
	dkStored, err := decodeB64(parts[5])
	if err != nil {
		return false
	}
	dk := argon2.IDKey([]byte(plain), salt, uint32(t), uint32(m), uint8(p), uint32(len(dkStored)))
	return subtle.ConstantTimeCompare(dk, dkStored) == 1
}
