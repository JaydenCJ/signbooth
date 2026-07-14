//go:build !unix

package audit

import "os"

// Non-unix builds fall back to the in-process mutex alone. signbooth's
// daemon transport is unix-socket-first, so these platforms are best-effort.
func lockFile(_ *os.File) error { return nil }

func unlockFile(_ *os.File) {}
