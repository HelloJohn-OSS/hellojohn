package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlPlaneWriter_WriteOnlySystemEvents(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "controlplane", "audit.log")
	w := NewControlPlaneWriter(path, nil)

	events := []AuditEvent{
		NewEvent(EventLogin, "tenant-a"),
		NewEvent(EventLoginFailed, ControlPlaneTenantID),
	}

	if err := w.Write(context.Background(), events); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 control-plane event line, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `"tenant_id":"system"`) {
		t.Fatalf("expected control-plane tenant in output line: %s", lines[0])
	}
}
