//go:build windows

package localruntime

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func processAlive(pid int) (bool, error) {
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH", "/FI", fmt.Sprintf("PID eq %d", pid))
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}

	reader := csv.NewReader(strings.NewReader(strings.TrimSpace(string(out))))
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if len(record) < 2 {
			continue
		}
		p, convErr := strconv.Atoi(strings.TrimSpace(record[1]))
		if convErr == nil && p == pid {
			return true, nil
		}
	}
}

func stopPID(pid int, timeout time.Duration) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
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
	return fmt.Errorf("process %d did not stop after Kill()", pid)
}

func applyBackgroundAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}
