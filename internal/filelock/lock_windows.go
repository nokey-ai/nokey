//go:build windows

package filelock

import (
	"os"

	"golang.org/x/sys/windows"
)

// Lock blocks until it holds an exclusive lock on the first byte of f.
func Lock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
}

// Unlock releases a lock taken with Lock.
func Unlock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}
