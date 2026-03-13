package localruntime

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestInitProfileLoadAndValidate(t *testing.T) {
	withTestHome(t, func(home string) {
		if err := InitProfile("default", false); err != nil {
			t.Fatalf("InitProfile() error = %v", err)
		}

		values, err := LoadProfile("default")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}

		if got := len(values["SIGNING_MASTER_KEY"]); got != 64 {
			t.Fatalf("SIGNING_MASTER_KEY length = %d, want 64", got)
		}
		if values["SECRETBOX_MASTER_KEY"] == "" {
			t.Fatalf("SECRETBOX_MASTER_KEY should not be empty")
		}

		if errs := ValidateProfile("default"); len(errs) != 0 {
			t.Fatalf("ValidateProfile() returned errors: %+v", errs)
		}
	})
}

func TestWriteProfilePreservesCommentsAndOrder(t *testing.T) {
	withTestHome(t, func(home string) {
		path := EnvFile("default")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}

		seed := strings.Join([]string{
			"# Header comment",
			"APP_ENV=dev",
			"# HELLOJOHN_TUNNEL_TOKEN=hjtun_placeholder",
			"BASE_URL=http://localhost:8080",
			"",
		}, "\n")
		if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		err := WriteProfile("default", map[string]string{
			"HELLOJOHN_TUNNEL_TOKEN": "hjtun_live_token",
			"APP_ENV":                "staging",
		})
		if err != nil {
			t.Fatalf("WriteProfile() error = %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		text := string(data)

		if !strings.Contains(text, "# Header comment") {
			t.Fatalf("expected header comment to be preserved, got:\n%s", text)
		}
		if !strings.Contains(text, "APP_ENV=staging") {
			t.Fatalf("expected APP_ENV to be updated, got:\n%s", text)
		}
		if strings.Contains(text, "# HELLOJOHN_TUNNEL_TOKEN=") {
			t.Fatalf("expected commented token placeholder to be activated, got:\n%s", text)
		}
		if !strings.Contains(text, "HELLOJOHN_TUNNEL_TOKEN=hjtun_live_token") {
			t.Fatalf("expected token to be written, got:\n%s", text)
		}

		appIndex := strings.Index(text, "APP_ENV=staging")
		baseIndex := strings.Index(text, "BASE_URL=http://localhost:8080")
		if appIndex == -1 || baseIndex == -1 || appIndex > baseIndex {
			t.Fatalf("expected APP_ENV to remain before BASE_URL, got:\n%s", text)
		}
	})
}

func TestRedactValue(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  bool
	}{
		{name: "suffix key", key: "API_KEY", value: "abc", want: true},
		{name: "suffix token", key: "HELLOJOHN_TUNNEL_TOKEN", value: "x", want: true},
		{name: "value prefix", key: "CUSTOM", value: "hjtun_123", want: true},
		{name: "plain value", key: "BASE_URL", value: "http://localhost:8080", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactValue(tc.key, tc.value); got != tc.want {
				t.Fatalf("RedactValue(%q, %q) = %v, want %v", tc.key, tc.value, got, tc.want)
			}
		})
	}
}

func TestProfileNameValidationRejectsTraversal(t *testing.T) {
	withTestHome(t, func(home string) {
		badProfiles := []string{
			"../../etc/passwd",
			"..\\..\\windows\\system32",
			"..",
			".",
			"nested/profile",
			"nested\\profile",
			"profile with spaces",
			"profile:colon",
			"C:drive",
		}

		for _, profile := range badProfiles {
			if err := InitProfile(profile, true); err == nil {
				t.Fatalf("InitProfile(%q) expected error, got nil", profile)
			}
			if _, err := LoadProfile(profile); err == nil {
				t.Fatalf("LoadProfile(%q) expected error, got nil", profile)
			}
			if err := WriteProfile(profile, map[string]string{"APP_ENV": "dev"}); err == nil {
				t.Fatalf("WriteProfile(%q) expected error, got nil", profile)
			}
		}
	})
}

// testHomeMu serialises calls to withTestHome because os.Setenv is global
// state — concurrent callers would race on HOME/USERPROFILE.
var testHomeMu sync.Mutex

func withTestHome(t *testing.T, fn func(home string)) {
	t.Helper()
	testHomeMu.Lock()
	defer testHomeMu.Unlock()

	home := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldUserProfile := os.Getenv("USERPROFILE")
	oldHomeDrive := os.Getenv("HOMEDRIVE")
	oldHomePath := os.Getenv("HOMEPATH")

	_ = os.Setenv("HOME", home)
	_ = os.Setenv("USERPROFILE", home)
	if runtime.GOOS == "windows" {
		_ = os.Setenv("HOMEDRIVE", "")
		_ = os.Setenv("HOMEPATH", "")
	}

	t.Cleanup(func() {
		_ = os.Setenv("HOME", oldHome)
		_ = os.Setenv("USERPROFILE", oldUserProfile)
		_ = os.Setenv("HOMEDRIVE", oldHomeDrive)
		_ = os.Setenv("HOMEPATH", oldHomePath)
	})

	fn(home)
}
