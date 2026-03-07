package password

import (
	"bufio"
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// ── Blacklist basada en archivo (backward compatible) ──

type Blacklist struct {
	mu   sync.RWMutex
	data map[string]struct{}
}

// global cached instance (lazy) to avoid re-reading the file on every request
var cached atomic.Pointer[Blacklist]
var loadOnce sync.Once
var cachedPath atomic.Pointer[string]

// GetCachedBlacklist returns a singleton blacklist for the provided path.
// If path changes between calls, it reloads once for the new path.
func GetCachedBlacklist(path string) (*Blacklist, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		// empty path => always return empty blacklist (no caching required)
		bl := cached.Load()
		if bl != nil {
			return bl, nil
		}
		empty := &Blacklist{data: map[string]struct{}{}}
		if cached.CompareAndSwap(nil, empty) {
			return empty, nil
		}
		return cached.Load(), nil
	}

	// If path matches existing cached path, just return.
	cp := cachedPath.Load()
	if cp != nil && *cp == p {
		if cur := cached.Load(); cur != nil {
			return cur, nil
		}
	}

	// Reload (not strictly single-flight; acceptable for startup race)
	bl, err := LoadBlacklist(p)
	if err != nil {
		return nil, err
	}
	cached.Store(bl)
	cachedPath.Store(&p)
	return bl, nil
}

func LoadBlacklist(path string) (*Blacklist, error) {
	bl := &Blacklist{data: map[string]struct{}{}}
	if strings.TrimSpace(path) == "" {
		return bl, nil
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(strings.ToLower(sc.Text()))
		if s != "" && !strings.HasPrefix(s, "#") {
			bl.data[s] = struct{}{}
		}
	}
	return bl, sc.Err()
}

func (b *Blacklist) Contains(pwd string) bool {
	if b == nil {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(pwd))
	b.mu.RLock()
	_, ok := b.data[p]
	b.mu.RUnlock()
	return ok
}

// ── CommonPasswordRule: PolicyRule con lista embebida (EPIC 1, Fase 1.5) ──

//go:embed common_passwords.txt
var commonPasswordData string

var badPasswords map[string]struct{}
var initBadPasswords sync.Once

func loadBadPasswords() {
	badPasswords = make(map[string]struct{})
	lines := strings.Split(commonPasswordData, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			badPasswords[strings.ToLower(l)] = struct{}{}
		}
	}
}

// CommonPasswordRule verifica que la contraseña no se encuentre en la lista
// de contraseñas más comunes (embebida vía go:embed).
type CommonPasswordRule struct{}

func (r CommonPasswordRule) Name() string { return "common_password" }

func (r CommonPasswordRule) Validate(password string, _ PolicyContext) *Violation {
	initBadPasswords.Do(loadBadPasswords)
	if _, found := badPasswords[strings.ToLower(password)]; found {
		return &Violation{
			Rule:    r.Name(),
			Message: "This password is too common and easily guessable.",
		}
	}
	return nil
}
