package localruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProcessState stores shared metadata for managed processes.
type ProcessState struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Profile   string    `json:"profile"`
}

// ServerState stores runtime metadata for the local server process.
type ServerState struct {
	ProcessState
	Port    int    `json:"port"`
	BaseURL string `json:"base_url"`
}

// TunnelState stores runtime metadata for the local tunnel process.
type TunnelState struct {
	ProcessState
	CloudURL    string `json:"cloud_url"`
	TokenPrefix string `json:"token_prefix"`
	Connected   bool   `json:"connected"`
}

// IsAlive checks whether the process referenced by pidFile is currently alive.
// If pidFile is missing, returns (false, 0, nil).
// If pidFile is stale, it is removed and returns (false, pid, nil).
func IsAlive(pidFile string) (bool, int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("read pid file %s: %w", pidFile, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		_ = os.Remove(pidFile)
		return false, 0, nil
	}

	alive, err := processAlive(pid)
	if err != nil {
		return false, pid, fmt.Errorf("check pid %d: %w", pid, err)
	}
	if !alive {
		_ = os.Remove(pidFile)
		return false, pid, nil
	}
	return true, pid, nil
}

// Spawn starts a detached background process and writes its PID to pidFile.
// stdout/stderr are redirected to logFile.
func Spawn(binary string, args []string, env []string, pidFile, logFile string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(pidFile), 0o755); err != nil {
		return 0, fmt.Errorf("create pid dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err != nil {
		return 0, fmt.Errorf("create log dir: %w", err)
	}

	logHandle, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, fmt.Errorf("open log file: %w", err)
	}
	defer logHandle.Close()

	cmd := exec.Command(binary, args...)
	cmd.Stdout = logHandle
	cmd.Stderr = logHandle
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), env...)
	applyBackgroundAttrs(cmd)

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start process %s: %w", binary, err)
	}
	pid := cmd.Process.Pid

	if err := writeFileAtomic(pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0o600); err != nil {
		_ = stopPID(pid, 2*time.Second)
		return 0, fmt.Errorf("write pid file: %w", err)
	}
	return pid, nil
}

// StopProcess terminates the process from pidFile and removes pid/state files.
func StopProcess(pidFile string, stateFile string, timeout time.Duration) error {
	alive, pid, err := IsAlive(pidFile)
	if err != nil {
		return err
	}

	if alive {
		if err := stopPID(pid, timeout); err != nil {
			return fmt.Errorf("stop pid %d: %w", pid, err)
		}
	}

	_ = os.Remove(pidFile)
	_ = os.Remove(stateFile)
	return nil
}

// WriteState atomically serializes a JSON state file.
func WriteState[T any](stateFile string, state T) error {
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	payload = append(payload, '\n')
	if err := writeFileAtomic(stateFile, payload, 0o600); err != nil {
		return fmt.Errorf("write state file %s: %w", stateFile, err)
	}
	return nil
}

// ReadState deserializes a JSON state file into T.
func ReadState[T any](stateFile string) (T, error) {
	var out T
	payload, err := os.ReadFile(stateFile)
	if err != nil {
		return out, fmt.Errorf("read state file %s: %w", stateFile, err)
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return out, fmt.Errorf("parse state file %s: %w", stateFile, err)
	}
	return out, nil
}
