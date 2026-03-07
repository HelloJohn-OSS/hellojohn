package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Sign genera una firma HMAC-SHA256 utilizando un payload rudo, una clave criptográfica (secret)
// y una estampa de tiempo (timestamp unix). La firma previene ataques de Man-in-the-Middle y Replay-attacks.
func Sign(payload []byte, secret string, timestamp int64) string {
	msg := fmt.Sprintf("%d.%s", timestamp, payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}
