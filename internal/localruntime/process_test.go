package localruntime

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteAndReadState(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	want := TunnelState{
		ProcessState: ProcessState{
			PID:       123,
			StartedAt: time.Now().UTC().Truncate(time.Second),
			Profile:   "default",
		},
		CloudURL:    "https://cloud.hellojohn.com",
		TokenPrefix: "hjtun_abc123",
		Connected:   true,
	}

	if err := WriteState(stateFile, want); err != nil {
		t.Fatalf("WriteState() error = %v", err)
	}

	got, err := ReadState[TunnelState](stateFile)
	if err != nil {
		t.Fatalf("ReadState() error = %v", err)
	}
	if got.PID != want.PID || got.Profile != want.Profile || got.CloudURL != want.CloudURL || !got.Connected {
		t.Fatalf("ReadState() = %+v, want %+v", got, want)
	}
}

func TestSpawnIsAliveAndStopProcess(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "worker.pid")
	stateFile := filepath.Join(dir, "worker.state.json")
	logFile := filepath.Join(dir, "worker.log")

	if err := os.WriteFile(stateFile, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile(state) error = %v", err)
	}

	pid, err := Spawn(
		os.Args[0],
		[]string{"-test.run=^TestManagedHelperProcess$", "--"},
		[]string{"GO_WANT_MANAGED_HELPER=1"},
		pidFile,
		logFile,
	)
	if err != nil {
		t.Fatalf("Spawn() error = %v", err)
	}
	if pid <= 0 {
		t.Fatalf("Spawn() pid = %d, want > 0", pid)
	}

	alive := false
	for i := 0; i < 25; i++ {
		ok, _, checkErr := IsAlive(pidFile)
		if checkErr != nil {
			t.Fatalf("IsAlive() error = %v", checkErr)
		}
		if ok {
			alive = true
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	if !alive {
		t.Fatalf("expected spawned process to be alive")
	}

	if err := StopProcess(pidFile, stateFile, 4*time.Second); err != nil {
		t.Fatalf("StopProcess() error = %v", err)
	}

	ok, _, err := IsAlive(pidFile)
	if err != nil {
		t.Fatalf("IsAlive() after stop error = %v", err)
	}
	if ok {
		t.Fatalf("expected process to be stopped")
	}
	if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
		t.Fatalf("expected state file to be removed, stat err=%v", err)
	}
}

func TestManagedHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_MANAGED_HELPER") != "1" {
		return
	}
	// Self-terminate after 60s so the helper does not leak in CI when the
	// parent test binary is killed or times out before calling StopProcess.
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	<-timer.C
}
