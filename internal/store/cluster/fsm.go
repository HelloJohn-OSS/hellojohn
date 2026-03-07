package clusterv2

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/raft"
)

// FSM implementa raft.FSM usando un Applier desacoplado.
// Es determinístico: solo deserializa y delega al Applier.
type FSM struct {
	applier Applier
	fsRoot  string // FS root para snapshots (vacío si no hay FS)
}

// NewFSM crea un FSM V2.
func NewFSM(applier Applier, fsRoot string) *FSM {
	return &FSM{applier: applier, fsRoot: fsRoot}
}

// Apply deserializa la mutación y delega al Applier.
// NO hace validaciones, NO genera IDs, NO usa time.Now().
func (f *FSM) Apply(l *raft.Log) interface{} {
	if l == nil || len(l.Data) == 0 {
		return nil
	}

	var m Mutation
	if err := json.Unmarshal(l.Data, &m); err != nil {
		return err
	}

	// Delegar al applier (que usa Store V2)
	if err := f.applier.Apply(m); err != nil {
		return err
	}

	return nil
}

// Snapshot crea un snapshot del estado (tenants/ y keys/ del FS root).
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	return &fsSnapshot{root: f.fsRoot}, nil
}

// Restore restaura el estado desde un snapshot.
func (f *FSM) Restore(rc io.ReadCloser) error {
	if rc == nil {
		return nil
	}
	defer rc.Close()

	if f.fsRoot == "" {
		// Sin FS root, consumir stream y descartar
		_, _ = io.Copy(io.Discard, rc)
		return nil
	}

	// Staging dir
	staging := filepath.Join(f.fsRoot, "restore.tmp")
	_ = os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0755); err != nil {
		return err
	}

	// Extract tar.gz
	gz, err := gzip.NewReader(rc)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Normalizar path
		n := strings.ReplaceAll(hdr.Name, "\\", "/")
		n = filepath.Clean(n)

		// Restringir a tenants/ y keys/
		if !(n == "tenants" || n == "keys" || strings.HasPrefix(n, "tenants/") || strings.HasPrefix(n, "keys/")) {
			continue
		}

		target := filepath.Join(staging, filepath.FromSlash(n))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, fs.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fs.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return err
			}
			file.Close()
		}
	}

	// Atomic swap de directorios
	for _, sub := range []string{"tenants", "keys"} {
		dst := filepath.Join(f.fsRoot, sub)
		src := filepath.Join(staging, sub)
		_ = os.MkdirAll(src, 0755) // Asegurar que existe

		bak := dst + ".bak"
		_ = os.RemoveAll(bak)
		if _, err := os.Stat(dst); err == nil {
			_ = os.Rename(dst, bak)
		}
		if err := os.Rename(src, dst); err != nil {
			// Rollback
			if _, stErr := os.Stat(bak); stErr == nil {
				_ = os.Rename(bak, dst)
			}
			return err
		}
		_ = os.RemoveAll(bak)
	}

	_ = os.RemoveAll(staging)
	return nil
}

// fsSnapshot implementa raft.FSMSnapshot.
type fsSnapshot struct {
	root string
}

func (s *fsSnapshot) Persist(sink raft.SnapshotSink) error {
	if s.root == "" {
		return sink.Close()
	}

	gw := gzip.NewWriter(sink)
	tw := tar.NewWriter(gw)

	// Helper para agregar archivos
	addFile := func(rel string, info os.FileInfo, full string) error {
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(full)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
		}
		return nil
	}

	// Walk tenants/ y keys/
	for _, sub := range []string{"tenants", "keys"} {
		base := filepath.Join(s.root, sub)
		if st, err := os.Stat(base); err != nil || !st.IsDir() {
			continue
		}
		if err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(s.root, path)
			rel = filepath.ToSlash(rel)
			if info.IsDir() {
				if rel == "" {
					return nil
				}
				return addFile(rel+"/", info, path)
			}
			return addFile(rel, info, path)
		}); err != nil {
			_ = gw.Close()
			_ = sink.Cancel()
			return err
		}
	}

	if err := tw.Close(); err != nil {
		gw.Close()
		sink.Cancel()
		return err
	}
	if err := gw.Close(); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

// Release no hace nada porque fsSnapshot no tiene recursos que liberar.
func (s *fsSnapshot) Release() {}
