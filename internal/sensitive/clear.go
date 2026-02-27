// Package sensitive provides best-effort memory zeroing for secret values.
//
// Go cannot guarantee full memory erasure — strings are immutable, the GC
// does not zero freed pages, and the runtime may copy objects at any time.
// These functions reduce the exposure window by zeroing the backing memory
// we can reach, as soon as we're done with it.
//
// Known limitations:
//
//  1. Strings copied by os/exec at execve time live in child process memory.
//  2. fmt.Sprintf intermediates (e.g. "KEY=value") create unreachable copies.
//  3. Freed memory is not zeroed by the GC — data persists until pages are reused.
//  4. Third-party libraries (keyring, argon2, oauth2) create their own copies.
//  5. Strings shorter than 8 bytes are skipped to avoid corrupting Go-interned strings.
//  6. The GC may theoretically move an object between our StringData call and
//     our zeroing, though this is extremely unlikely in practice.
//  7. Strings backed by read-only memory (e.g. literals) cannot be zeroed;
//     the attempt is silently skipped.
package sensitive

import (
	"runtime/debug"
	"unsafe"
)

// ClearBytes zeros a byte slice in-place.
func ClearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ClearMap zeros every value in the map, then deletes all keys.
// Keys (secret names) are not considered sensitive and are not zeroed.
func ClearMap(m map[string]string) {
	for k, v := range m {
		clearString(v)
		delete(m, k)
	}
}

// ClearSlice zeros every element's backing memory, then sets each to "".
func ClearSlice(ss []string) {
	for i, s := range ss {
		clearString(s)
		ss[i] = ""
	}
}

// ClearString zeros the backing bytes of a string. Exported because callers
// in auth need to clear individual PIN strings.
//
// Strings shorter than 8 bytes are skipped to avoid corrupting Go runtime
// interned short strings. Strings backed by read-only memory (literals) are
// silently skipped.
func ClearString(s string) {
	clearString(s)
}

// clearString is the internal implementation. It uses unsafe.StringData
// (Go 1.20+) to obtain the backing array pointer, then zeros len(s) bytes.
//
// To safely handle read-only memory (string literals in rodata), we:
//  1. Use a //go:noinline helper so the compiler can't optimize the write
//     into runtime.memclrNoHeapPointers (faults in runtime code are fatal).
//  2. Set debug.SetPanicOnFault(true) so any SIGBUS/SIGSEGV from writing
//     read-only memory becomes a recoverable panic instead of a fatal throw.
func clearString(s string) {
	if len(s) < 8 {
		return
	}
	p := unsafe.StringData(s)
	if p == nil {
		return
	}

	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	defer func() { recover() }() //nolint:errcheck // intentionally swallowing fault panics

	for i := range len(s) {
		zeroByteAt(unsafe.Add(unsafe.Pointer(p), i))
	}
}

// zeroByteAt writes a zero byte at the given pointer. It is kept
// non-inlineable so the compiler cannot fold the caller's loop into
// runtime.memclrNoHeapPointers, which would make faults unrecoverable.
//
//go:noinline
func zeroByteAt(p unsafe.Pointer) {
	*(*byte)(p) = 0
}
