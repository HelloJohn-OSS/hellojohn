package social

import (
	"testing"
)

func TestRegistryRegisterAndBuild(t *testing.T) {
	r := NewRegistry()
	if r.Has("google") {
		t.Fatal("expected empty registry")
	}
	if len(r.List()) != 0 {
		t.Fatal("expected 0 providers")
	}

	// Register a nil factory just to test registry mechanics
	r.Register("test", nil)
	if !r.Has("test") {
		t.Fatal("expected 'test' to be registered")
	}
	if len(r.List()) != 1 {
		t.Fatal("expected 1 provider")
	}
}

func TestRegistryHasCaseInsensitive(t *testing.T) {
	r := NewRegistry()
	r.Register("Google", nil)

	if !r.Has("google") {
		t.Error("Has should be case-insensitive (lowercase)")
	}
	if !r.Has("GOOGLE") {
		t.Error("Has should be case-insensitive (uppercase)")
	}
	if !r.Has("Google") {
		t.Error("Has should be case-insensitive (mixed)")
	}
}

func TestRegistryBuildUnknown(t *testing.T) {
	r := NewRegistry()
	_, err := r.Build(nil, "nonexistent", "slug", "http://localhost")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}
