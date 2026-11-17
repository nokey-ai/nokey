//go:build !windows

// Package filelock takes advisory locks on files, to serialize work across
// nokey processes.
package filelock

import (
	"os"

	"golang.org/x/sys/unix"
)

// Lock blocks until it holds an exclusive flock on f.
func Lock(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			return err
		}
	}
}

// Unlock releases a lock taken with Lock.
func Unlock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
