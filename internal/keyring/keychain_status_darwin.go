//go:build darwin

package keyring

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>

static int nk_keychain_unlocked(const char *path) {
	SecKeychainRef kc;
	if (SecKeychainOpen(path, &kc) != errSecSuccess) return 0;
	SecKeychainStatus status = 0;
	OSStatus s = SecKeychainGetStatus(kc, &status);
	CFRelease(kc);
	return s == errSecSuccess && (status & kSecUnlockStateStatus) != 0;
}
*/
import "C"

import "unsafe"

// KeychainUnlocked reports whether the keychain file at path exists and is
// currently unlocked. Checking never prompts.
func KeychainUnlocked(path string) bool {
	if path == "" {
		return false
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	return C.nk_keychain_unlocked(cPath) != 0
}
