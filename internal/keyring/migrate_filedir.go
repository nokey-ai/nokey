package keyring

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// reservedConfigFiles lists files that nokey itself writes into ConfigDir
// alongside (legacy) file-backend secrets. The file-backend keyring library
// treats every file in its FileDir as a keyring item, so these names must
// NOT be moved into the keyring subdirectory when migrating an old layout —
// they are owned by other subsystems (config, audit, session).
var reservedConfigFiles = map[string]struct{}{
	"config.yaml":     {},
	"policies.yaml":   {},
	"audit.log":       {},
	"chain_head.json": {},
	"session_ticket":  {},
}

// migrateFileBackendDir relocates legacy file-backend keyring entries from
// oldDir (historically the nokey ConfigDir itself) into newDir, leaving
// reserved config/audit/session files in place.
//
// Safety properties:
//   - If newDir already exists, returns nil — never re-migrates.
//   - If oldDir is missing or empty of candidates, returns nil.
//   - Each candidate is copied (with fsync) to a temp name in newDir,
//     verified by size, atomically renamed into place, and only then
//     removed from oldDir. A failure aborts the migration with the
//     original files still intact.
//   - Reserved files, dot-files, and subdirectories are skipped.
//
// Intended to be called once per process at file-backend open time; the
// idempotent early-return makes repeat calls cheap.
func migrateFileBackendDir(oldDir, newDir string) error {
	// Idempotent: if the new layout already exists, never touch the old one.
	if _, err := os.Stat(newDir); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", newDir, err)
	}

	entries, err := os.ReadDir(oldDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", oldDir, err)
	}

	candidates := make([]os.DirEntry, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		if len(name) > 0 && name[0] == '.' {
			continue
		}
		if _, reserved := reservedConfigFiles[name]; reserved {
			continue
		}
		candidates = append(candidates, e)
	}

	if len(candidates) == 0 {
		return nil
	}

	if err := os.MkdirAll(newDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", newDir, err)
	}

	for _, e := range candidates {
		src := filepath.Join(oldDir, e.Name())
		dst := filepath.Join(newDir, e.Name())
		if err := safeMoveFile(src, dst); err != nil {
			return fmt.Errorf("migrate %s: %w", e.Name(), err)
		}
	}
	return nil
}

// safeMoveFile copies src to dst.tmp, fsyncs, verifies size, renames over
// dst, then removes src. Any failure leaves src untouched on disk.
func safeMoveFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	dstInfo, err := os.Stat(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if dstInfo.Size() != info.Size() {
		_ = os.Remove(tmp)
		return fmt.Errorf("size mismatch after copy: src=%d dst=%d", info.Size(), dstInfo.Size())
	}

	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Remove(src)
}
