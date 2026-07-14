//go:build unix

package audit

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock, blocking until it is granted.
// Appends are tiny, so contention windows are microseconds.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
