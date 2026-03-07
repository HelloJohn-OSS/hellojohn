package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileWriter durably persists audit events as JSON Lines.
// Intended for overflow fallback so events are not silently dropped.
type FileWriter struct {
	path   string
	logger *log.Logger
	mu     sync.Mutex
}

// NewFileWriter creates a durable JSONL writer for audit events.
func NewFileWriter(path string, logger *log.Logger) *FileWriter {
	if logger == nil {
		logger = log.Default()
	}
	return &FileWriter{
		path:   strings.TrimSpace(path),
		logger: logger,
	}
}

// Write appends all events to the configured file as JSON lines.
func (w *FileWriter) Write(ctx context.Context, events []AuditEvent) error {
	if w == nil || len(events) == 0 {
		return nil
	}
	if w.path == "" {
		return errors.New("audit file writer path is empty")
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

	for _, e := range events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		b, err := json.Marshal(e)
		if err != nil {
			if w.logger != nil {
				w.logger.Printf("audit: marshal file event failed: %v", err)
			}
			continue
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
	}

	return f.Sync()
}
