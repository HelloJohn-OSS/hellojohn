package jwt

import (
	"encoding/json"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// buildJWKS construye JWKS JSON a partir de un slice de SigningKey.
// Deprecated: usar repository.JWKS directamente cuando sea posible.
func buildJWKS(keys []repository.SigningKey) []byte {
	jwks := repository.JWKS{
		Keys: make([]repository.JWK, 0, len(keys)),
	}

	for _, k := range keys {
		if k.PublicKey == nil {
			continue
		}

		// Obtener bytes de la clave pública
		var pubBytes []byte
		switch pk := k.PublicKey.(type) {
		case []byte:
			pubBytes = pk
		default:
			// Para ed25519.PublicKey u otros
			continue
		}

		jwks.Keys = append(jwks.Keys, repository.JWK{
			KID: k.ID,
			Kty: "OKP",
			Crv: "Ed25519",
			Alg: k.Algorithm,
			Use: "sig",
			X:   EncodeBase64URL(pubBytes),
		})
	}

	b, _ := json.Marshal(jwks)
	return b
}
