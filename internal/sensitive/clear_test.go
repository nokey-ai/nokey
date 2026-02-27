package sensitive

import (
	"testing"
	"unsafe"
)

// heapString forces a string onto the heap (string literals live in read-only
// memory and can't be zeroed). In production, all secret values come from
// runtime operations (keyring reads, network I/O) and are heap-allocated.
func heapString(s string) string {
	b := make([]byte, len(s))
	copy(b, s)
	return string(b)
}

func TestClearBytes(t *testing.T) {
	b := []byte("supersecretvalue")
	ClearBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("ClearBytes: byte %d is %d, want 0", i, v)
		}
	}
}

func TestClearBytesNil(t *testing.T) {
	ClearBytes(nil) // must not panic
}

func TestClearBytesEmpty(t *testing.T) {
	ClearBytes([]byte{}) // must not panic
}

func TestClearMap(t *testing.T) {
	m := map[string]string{
		"KEY1": heapString("this-is-a-secret-value-1"),
		"KEY2": heapString("this-is-a-secret-value-2"),
	}

	// Capture backing pointers before clearing.
	type entry struct {
		ptr *byte
		len int
	}
	entries := make([]entry, 0, len(m))
	for _, v := range m {
		p := unsafe.StringData(v)
		entries = append(entries, entry{ptr: p, len: len(v)})
	}

	ClearMap(m)

	if len(m) != 0 {
		t.Fatalf("ClearMap: map still has %d entries", len(m))
	}

	// Verify backing bytes are zeroed.
	for _, e := range entries {
		b := unsafe.Slice(e.ptr, e.len)
		for i, v := range b {
			if v != 0 {
				t.Fatalf("ClearMap: backing byte %d is %d, want 0", i, v)
			}
		}
	}
}

func TestClearMapNil(t *testing.T) {
	ClearMap(nil) // must not panic
}

func TestClearMapEmpty(t *testing.T) {
	ClearMap(map[string]string{}) // must not panic
}

func TestClearSlice(t *testing.T) {
	ss := []string{
		heapString("this-is-a-long-secret-1"),
		heapString("this-is-a-long-secret-2"),
	}

	// Capture backing pointers.
	type entry struct {
		ptr *byte
		len int
	}
	entries := make([]entry, len(ss))
	for i, s := range ss {
		entries[i] = entry{ptr: unsafe.StringData(s), len: len(s)}
	}

	ClearSlice(ss)

	for i, s := range ss {
		if s != "" {
			t.Fatalf("ClearSlice: element %d is %q, want empty", i, s)
		}
	}

	for _, e := range entries {
		b := unsafe.Slice(e.ptr, e.len)
		for j, v := range b {
			if v != 0 {
				t.Fatalf("ClearSlice: backing byte %d is %d, want 0", j, v)
			}
		}
	}
}

func TestClearSliceNil(t *testing.T) {
	ClearSlice(nil) // must not panic
}

func TestClearStringShort(t *testing.T) {
	// Short strings (< 8 bytes) should be skipped — no crash, no corruption.
	ClearString(heapString("short"))
	ClearString("")
	ClearString("a")
}

func TestClearStringReadOnly(t *testing.T) {
	// String literals live in read-only memory. ClearString must not crash.
	ClearString("this-is-a-read-only-string-literal")
}

func TestClearMapReadOnly(t *testing.T) {
	// Map with string literal values — must not crash.
	m := map[string]string{
		"KEY": "this-is-a-read-only-literal-value",
	}
	ClearMap(m)
	if len(m) != 0 {
		t.Fatalf("ClearMap: map still has %d entries", len(m))
	}
}

func TestClearStringLong(t *testing.T) {
	s := heapString("this-is-a-longer-secret-value")
	p := unsafe.StringData(s)
	n := len(s)

	ClearString(s)

	b := unsafe.Slice(p, n)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("ClearString: backing byte %d is %d, want 0", i, v)
		}
	}
}
