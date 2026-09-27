module github.com/redstone/customapi

go 1.26

// Deliberately dependency-free: the customs gateway must build with the Go
// standard library alone so it can be compiled for FreeBSD without CGO and
// without needing a module proxy at deploy time.
