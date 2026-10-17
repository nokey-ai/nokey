//go:build !windows

package audit

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile blocks until it holds an exclusive flock on f.
func lockFile(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
