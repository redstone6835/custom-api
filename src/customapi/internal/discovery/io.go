package discovery

import (
	"os"
	"path/filepath"
)

// readFile reads a file, returning the raw error so the caller can test for
// absence with os.IsNotExist.
func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// isNotExist reports whether an error means "no such file".
func isNotExist(err error) bool { return os.IsNotExist(err) }

// writeFileAtomic writes a file via a temporary rename so that a crash mid-write
// cannot leave a truncated cache behind.
func writeFileAtomic(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
