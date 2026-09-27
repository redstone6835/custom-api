//go:build !unix

package audit

import "io/fs"

// fileOwner is unsupported on this platform; the caller tolerates -1.
func fileOwner(fs.FileInfo) (uid, gid int) { return -1, -1 }
