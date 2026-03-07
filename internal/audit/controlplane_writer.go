package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// ControlPlaneWriter durably persists control-plane audit events
// (TenantID == ControlPlaneTenantID) as JSON Lines.
type ControlPlaneWriter struct {
	path   string
	logger *log.Logger
	mu     sync.Mutex
}

// NewControlPlaneWriter creates a durable writer for control-plane events.
func NewControlPlaneWriter(path string, logger *log.Logger) *ControlPlaneWriter {
	if logger == nil {
		logger = log.Default()
	}
	return &ControlPlaneWriter{
		path:   path,
		logger: logger,
	}
}

// Write appends control-plane events to a local JSONL file.
func (w *ControlPlaneWriter) Write(ctx context.Context, events []AuditEvent) error {
	if w == nil || len(events) == 0 {
		return nil
	}

	controlEvents := make([]AuditEvent, 0, len(events))
	for _, e := range events {
		if e.TenantID == ControlPlaneTenantID {
			controlEvents = append(controlEvents, e)
		}
	}
	if len(controlEvents) == 0 {
		return nil
	}

	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	for _, e := range controlEvents {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) && w.logger != nil {
				w.logger.Printf("audit: control-plane writer timeout after partial write")
			}
			return ctx.Err()
		default:
		}

		b, err := json.Marshal(e)
		if err != nil {
			if w.logger != nil {
				w.logger.Printf("audit: marshal control-plane event failed: %v", err)
			}
			continue
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
	}

	if err := f.Sync(); err != nil {
		return err
	}

	return nil
}
