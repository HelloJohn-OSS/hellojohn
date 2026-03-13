//go:build !windows

package localruntime

import "os"

func replaceFileAtomic(src, dst string) error {
	return os.Rename(src, dst)
}
