package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

const lockFileName = "audit.lock"

// lockAuditDir takes the advisory lock that serializes audit log access
// across processes — the CLI, the proxy and the MCP server all record — and
// returns the function that releases it. recordMu only covers callers within
// one process.
//
// The lock file is never removed: deleting it while another process waits on
// it would let a third process lock a fresh file and run alongside.
func lockAuditDir() (func(), error) {
	dir, err := AuditLogDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	f, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit lock: %w", err)
	}
	return lockOpened(f)
}

// lockAuditDirForLoad is lockAuditDir for Load, which only reads in the
// normal case and so must not fail, or create the audit dir, where it cannot
// write. An existing lock file is opened read-only, which flock and
// LockFileEx accept. If there is none and it cannot be created, Load runs
// unlocked, as it did before the lock existed.
func lockAuditDirForLoad() (func(), error) {
	dir, err := AuditLogDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, lockFileName)

	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) {
			return func() {}, nil
		}
		return nil, fmt.Errorf("failed to open audit lock: %w", err)
	}
	return lockOpened(f)
}

// lockOpened takes the lock on f and returns the function that releases it
// and closes f.
func lockOpened(f *os.File) (func(), error) {
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to lock audit log: %w", err)
	}

	return func() {
		_ = unlockFile(f)
		_ = f.Close()
	}, nil
}
