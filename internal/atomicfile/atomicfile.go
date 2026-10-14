// Package atomicfile writes a file so an interrupted write can never leave a
// truncated one behind.
//
// It is deliberately untagged (no goexperiment.simd) and imports only the
// standard library, so the untagged generators that use it keep building on a
// stock toolchain.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write writes data to path atomically: it creates a temporary file in the
// same directory, writes, syncs and closes it, gives it mode 0o644, and
// renames it over path, so an interrupted write can never leave a truncated
// file behind. The temporary file is removed if any step fails.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	tmp := f.Name()
	// The rename below consumes tmp; on any earlier return the deferred removal
	// reclaims it. After a successful rename the removal is a harmless ENOENT.
	defer os.Remove(tmp)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	return nil
}
