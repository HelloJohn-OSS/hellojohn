package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// canonicalJSON returns a deterministic JSON representation of v.
// It sorts map keys to ensure stability.
// Note: This is computationally expensive, use only for ETag generation on reasonable sized objects.
func canonicalJSON(v any) ([]byte, error) {
	// Simple approach: Use generic map for structure and sort keys manually or use a library.
	// Since we don't have a canonical json lib, we can marshal to a specific intermediate representation.
	// However, Go's json.Marshal sorts map keys by default!
	// "Map values encode as JSON objects. The map's key type must either be a string... The map keys are sorted and used as JSON object keys..."
	// Source: https://pkg.go.dev/encoding/json#Marshal

	// So simply marshaling should be enough for determinism IF the struct fields order is fixed (it is)
	// and maps are used.
	// But whitespace might vary? No, standard Marshal is compact.

	return json.Marshal(v)
}

// computeETag calculates a weak ETag based on the content.
// Format: "8-byte-hex" (quoted)
func computeETag(content any) (string, error) {
	b, err := canonicalJSON(content)
	if err != nil {
		return "", err
	}

	h := sha256.Sum256(b)
	// Truncate to 8 bytes (16 hex chars)
	// Using "W/" prefix? RFC says for semantic change. Here we use Strong ETag effectively for simpler client logic unless we want caching.
	// "abcd1234..."

	etag := hex.EncodeToString(h[:8])
	return fmt.Sprintf(`"%s"`, etag), nil
}
