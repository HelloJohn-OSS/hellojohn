//go:build !windows

package localruntime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func processAlive(pid int) (bool, error) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return false, nil
		}
		if errors.Is(err, syscall.EPERM) {
			return true, nil
		}
		return false, err
	}
	return true, nil
}

func stopPID(pid int, timeout time.Duration) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, err := processAlive(pid)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
		time.Sleep(120 * time.Millisecond)
	}

	if err := process.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("send SIGKILL: %w", err)
	}

	killDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(killDeadline) {
		alive, err := processAlive(pid)
		if err != nil {
			return err
		}
		if !alive {
			return nil
		}
		time.Sleep(80 * time.Millisecond)
	}

	return fmt.Errorf("process %d did not stop after SIGKILL", pid)
}

func applyBackgroundAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}
