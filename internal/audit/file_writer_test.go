package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileWriter_Write_PersistsAllEvents(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit-overflow.log")
	w := NewFileWriter(path, nil)

	events := []AuditEvent{
		NewEvent(EventLogin, "tenant-a"),
		NewEvent(EventLoginFailed, "tenant-b"),
		NewEvent(EventTenantUpdated, ControlPlaneTenantID),
	}
	if err := w.Write(context.Background(), events); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != len(events) {
		t.Fatalf("expected %d lines, got %d", len(events), len(lines))
	}

	for i, line := range lines {
		var got AuditEvent
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("invalid json line %d: %v", i, err)
		}
		if got.TenantID != events[i].TenantID {
			t.Fatalf("line %d tenant mismatch: got %q want %q", i, got.TenantID, events[i].TenantID)
		}
	}
}

func TestFileWriter_Write_EmptyPathReturnsError(t *testing.T) {
	t.Parallel()

	w := NewFileWriter("   ", nil)
	err := w.Write(context.Background(), []AuditEvent{NewEvent(EventLogin, "tenant-a")})
	if err == nil {
		t.Fatalf("expected error for empty path")
	}
}
