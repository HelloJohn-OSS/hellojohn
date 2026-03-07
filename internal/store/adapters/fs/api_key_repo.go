package fs

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"gopkg.in/yaml.v3"
)

// Compile-time check
var _ repository.APIKeyRepository = (*fsAPIKeyRepo)(nil)

type fsAPIKeyRepo struct {
	dir string
	mu  sync.RWMutex
}

func newAPIKeyRepo(fsRoot string) *fsAPIKeyRepo {
	return &fsAPIKeyRepo{dir: filepath.Join(fsRoot, "api_keys")}
}

// keyYAML es la representación en disco. Campos opcionales con omitempty.
type keyYAML struct {
	ID         string     `yaml:"id"`
	Name       string     `yaml:"name"`
	KeyPrefix  string     `yaml:"key_prefix"`
	KeyHash    string     `yaml:"key_hash"`
	Scope      string     `yaml:"scope"`
	CreatedBy  string     `yaml:"created_by"`
	CreatedAt  time.Time  `yaml:"created_at"`
	LastUsedAt *time.Time `yaml:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `yaml:"expires_at,omitempty"`
	RevokedAt  *time.Time `yaml:"revoked_at,omitempty"`
}

func toYAML(k repository.APIKey) keyYAML {
	return keyYAML{
		ID: k.ID, Name: k.Name, KeyPrefix: k.KeyPrefix,
		KeyHash: k.KeyHash, Scope: k.Scope, CreatedBy: k.CreatedBy,
		CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
		ExpiresAt: k.ExpiresAt, RevokedAt: k.RevokedAt,
	}
}

func fromYAML(y keyYAML) repository.APIKey {
	return repository.APIKey{
		ID: y.ID, Name: y.Name, KeyPrefix: y.KeyPrefix,
		KeyHash: y.KeyHash, Scope: y.Scope, CreatedBy: y.CreatedBy,
		CreatedAt: y.CreatedAt, LastUsedAt: y.LastUsedAt,
		ExpiresAt: y.ExpiresAt, RevokedAt: y.RevokedAt,
	}
}

func (r *fsAPIKeyRepo) filePath(id string) string {
	clean := filepath.Clean(filepath.Join(r.dir, id+".yaml"))
	// Reject path traversal: the result must stay inside r.dir.
	if !strings.HasPrefix(clean, r.dir+string(filepath.Separator)) {
		return ""
	}
	return clean
}

func (r *fsAPIKeyRepo) ensureDir() error {
	return os.MkdirAll(r.dir, 0700)
}

func (r *fsAPIKeyRepo) writeKey(k keyYAML) error {
	p := r.filePath(k.ID)
	if p == "" {
		return fmt.Errorf("api_key_repo: invalid key id")
	}
	data, err := yaml.Marshal(k)
	if err != nil {
		return fmt.Errorf("api_key_repo: marshal: %w", err)
	}
	return os.WriteFile(p, data, 0600)
}

func (r *fsAPIKeyRepo) readKey(path string) (keyYAML, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return keyYAML{}, err
	}
	var y keyYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return keyYAML{}, fmt.Errorf("api_key_repo: unmarshal %s: %w", path, err)
	}
	return y, nil
}

func (r *fsAPIKeyRepo) Create(ctx context.Context, key repository.APIKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensureDir(); err != nil {
		return fmt.Errorf("api_key_repo: create dir: %w", err)
	}
	return r.writeKey(toYAML(key))
}

// GetByHash itera todos los archivos y compara hashes con constant-time compare
// para prevenir timing attacks. Es O(n) sobre el número de keys — aceptable
// porque el número de API keys es pequeño (decenas, no millones).
func (r *fsAPIKeyRepo) GetByHash(ctx context.Context, hash string) (*repository.APIKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries, err := os.ReadDir(r.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("api_key_repo: readdir: %w", err)
	}

	hashBytes := []byte(hash)

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		y, err := r.readKey(filepath.Join(r.dir, e.Name()))
		if err != nil {
			log.Printf("[WARN] api_key_repo: skipping unreadable key file %s: %v", e.Name(), err)
			continue // archivo corrupto → saltar
		}
		// CRÍTICO: constant-time compare para evitar timing oracle
		if subtle.ConstantTimeCompare([]byte(y.KeyHash), hashBytes) == 1 {
			k := fromYAML(y)
			return &k, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r *fsAPIKeyRepo) List(ctx context.Context) ([]repository.APIKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries, err := os.ReadDir(r.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []repository.APIKey{}, nil
		}
		return nil, fmt.Errorf("api_key_repo: readdir: %w", err)
	}

	var keys []repository.APIKey
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		y, err := r.readKey(filepath.Join(r.dir, e.Name()))
		if err != nil {
			continue
		}
		keys = append(keys, fromYAML(y))
	}
	return keys, nil
}

func (r *fsAPIKeyRepo) GetByID(ctx context.Context, id string) (*repository.APIKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p := r.filePath(id)
	if p == "" {
		return nil, repository.ErrNotFound
	}
	y, err := r.readKey(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("api_key_repo: read: %w", err)
	}
	k := fromYAML(y)
	return &k, nil
}

func (r *fsAPIKeyRepo) Revoke(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.filePath(id)
	if p == "" {
		return repository.ErrNotFound
	}
	y, err := r.readKey(p)
	if err != nil {
		if os.IsNotExist(err) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("api_key_repo: read for revoke: %w", err)
	}
	if y.RevokedAt != nil {
		return nil // ya revocada — idempotente
	}
	now := time.Now().UTC()
	y.RevokedAt = &now
	return r.writeKey(y)
}

func (r *fsAPIKeyRepo) UpdateLastUsed(ctx context.Context, id string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.filePath(id)
	if p == "" {
		return nil // best-effort: invalid id, ignore
	}
	y, err := r.readKey(p)
	if err != nil {
		return nil // best-effort: ignorar si no existe
	}
	utc := at.UTC()
	y.LastUsedAt = &utc
	if err := r.writeKey(y); err != nil {
		// best-effort: log but do not fail the request
		log.Printf("[WARN] fs: api_key UpdateLastUsed for key %s: %v", id, err)
	}
	return nil
}
