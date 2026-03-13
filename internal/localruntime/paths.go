package localruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BaseDir returns the root directory used by the local runtime.
func BaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ".hellojohn"
	}
	return filepath.Join(home, ".hellojohn")
}

// EnvDir returns the directory that stores profile env files.
func EnvDir() string {
	return filepath.Join(BaseDir(), "env")
}

// EnvFile returns the profile-specific env file path.
func EnvFile(profile string) string {
	return filepath.Join(EnvDir(), sanitizeProfile(profile)+".env")
}

// RunDir returns the local runtime run directory (pid/state/log files).
func RunDir() string {
	return filepath.Join(BaseDir(), "run")
}

// BinDir returns the location where local binaries are expected.
func BinDir() string {
	return filepath.Join(BaseDir(), "bin")
}

func ServerPIDFile() string {
	return filepath.Join(RunDir(), "hellojohn.pid")
}

func ServerStateFile() string {
	return filepath.Join(RunDir(), "state.json")
}

func ServerLogFile() string {
	return filepath.Join(RunDir(), "hellojohn.log")
}

func TunnelPIDFile() string {
	return filepath.Join(RunDir(), "tunnel.pid")
}

func TunnelStateFile() string {
	return filepath.Join(RunDir(), "tunnel.state.json")
}

func TunnelLogFile() string {
	return filepath.Join(RunDir(), "tunnel.log")
}

func sanitizeProfile(profile string) string {
	normalized, err := normalizeProfileName(profile)
	if err != nil {
		return "default"
	}
	return normalized
}

// ValidateProfileName validates that a profile name is safe for filesystem use.
func ValidateProfileName(profile string) error {
	_, err := normalizeProfileName(profile)
	return err
}

func normalizeProfileName(profile string) (string, error) {
	p := strings.TrimSpace(profile)
	if p == "" {
		return "default", nil
	}

	if p == "." || p == ".." {
		return "", fmt.Errorf("invalid profile name %q", profile)
	}
	if strings.Contains(p, "..") || strings.ContainsAny(p, `/\ :`) {
		return "", fmt.Errorf("invalid profile name %q: must not contain path separators, spaces, or colons", profile)
	}
	if filepath.Base(p) != p {
		return "", fmt.Errorf("invalid profile name %q", profile)
	}

	return p, nil
}
