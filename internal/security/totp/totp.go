package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

// GenerateSecret retorna 20 bytes base32 sin padding (RFC 3548).
func GenerateSecret() (raw []byte, b32 string, err error) {
	raw = make([]byte, 20)
	_, err = rand.Read(raw)
	if err != nil {
		return nil, "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return raw, enc, nil
}

// OTPAuthURL construye otpauth:// para QR.
func OTPAuthURL(issuer, accountName, secretB32 string) string {
	// otpauth://totp/{issuer}:{account}?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
	label := url.PathEscape(fmt.Sprintf("%s:%s", issuer, accountName))
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}

// Verify TOTP en ventana +/- windowSteps (default 1). Evita replay comparando el contador con lastCounterUsed.
func Verify(secretRaw []byte, code string, t time.Time, windowSteps int, lastCounterUsed *int64) (ok bool, counter int64) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false, 0
	}
	// período de 30s
	counter = t.Unix() / 30
	start := counter - int64(windowSteps)
	end := counter + int64(windowSteps)
	for c := start; c <= end; c++ {
		if lastCounterUsed != nil && c <= *lastCounterUsed {
			continue // anti-replay
		}
		if gen(secretRaw, c) == code {
			return true, c
		}
	}
	return false, 0
}

func gen(secretRaw []byte, counter int64) string {
	// HOTP(K, C) con HMAC-SHA1 (RFC 4226 / 6238)
	var msg [8]byte
	for i := 7; i >= 0; i-- {
		msg[i] = byte(counter & 0xff)
		counter >>= 8
	}
	m := hmac.New(sha1.New, secretRaw)
	_, _ = m.Write(msg[:])
	sum := m.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	bin := (int(sum[offset])&0x7f)<<24 | int(sum[offset+1])<<16 | int(sum[offset+2])<<8 | int(sum[offset+3])
	otp := bin % int(math.Pow10(6))
	return fmt.Sprintf("%06d", otp)
}
