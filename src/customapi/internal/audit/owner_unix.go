//go:build unix

package audit

import (
	"io/fs"
	"syscall"
)

// fileOwner extracts the numeric owner and group of a file.
func fileOwner(info fs.FileInfo) (uid, gid int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}
