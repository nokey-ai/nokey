//go:build darwin

package keyring

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// Declared in Apple's private SecKeychainItemPriv.h and exported by
// Security.framework; /usr/bin/security uses it for
// set-generic-password-partition-list. The public SecKeychainItemSetAccess
// asks the user to confirm each change instead of taking the password.
extern OSStatus SecKeychainItemSetAccessWithPassword(SecKeychainItemRef itemRef, SecAccessRef accessRef, UInt32 passwordLength, const void *password);

// nk_self_cdhash writes the running binary's cdhash as 40 hex characters
// into out and sets *has_cert when it is signed with a certificate rather
// than ad-hoc.
static OSStatus nk_self_cdhash(char out[41], int *has_cert) {
	SecCodeRef code = NULL;
	SecStaticCodeRef staticCode = NULL;
	CFDictionaryRef info = NULL;
	OSStatus s = SecCodeCopySelf(kSecCSDefaultFlags, &code);
	if (s != errSecSuccess) return s;
	s = SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &staticCode);
	CFRelease(code);
	if (s != errSecSuccess) return s;
	s = SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation, &info);
	CFRelease(staticCode);
	if (s != errSecSuccess) return s;

	CFDataRef unique = CFDictionaryGetValue(info, kSecCodeInfoUnique);
	CFArrayRef certs = CFDictionaryGetValue(info, kSecCodeInfoCertificates);
	*has_cert = certs != NULL && CFArrayGetCount(certs) > 0;
	if (unique == NULL || CFDataGetLength(unique) < 20) {
		CFRelease(info);
		return errSecCSUnsigned;
	}
	const UInt8 *p = CFDataGetBytePtr(unique);
	for (int i = 0; i < 20; i++) snprintf(out + 2 * i, 3, "%02x", p[i]);
	CFRelease(info);
	return errSecSuccess;
}

// nk_partitions decodes a partition-list ACL description: a hex-encoded
// property list of the form {Partitions: [string, ...]}. Returns NULL if
// the description isn't one.
static CFArrayRef nk_partitions(CFStringRef desc) {
	char buf[8192];
	if (!CFStringGetCString(desc, buf, sizeof buf, kCFStringEncodingUTF8)) return NULL;
	size_t n = strlen(buf);
	if (n == 0 || n % 2 != 0) return NULL;
	UInt8 *bytes = malloc(n / 2);
	if (bytes == NULL) return NULL;
	for (size_t i = 0; i < n / 2; i++) {
		unsigned int b;
		if (sscanf(buf + 2 * i, "%2x", &b) != 1) { free(bytes); return NULL; }
		bytes[i] = (UInt8)b;
	}
	CFDataRef data = CFDataCreate(NULL, bytes, (CFIndex)(n / 2));
	free(bytes);
	CFPropertyListRef plist = CFPropertyListCreateWithData(NULL, data, kCFPropertyListImmutable, NULL, NULL);
	CFRelease(data);
	if (plist == NULL) return NULL;
	CFArrayRef result = NULL;
	if (CFGetTypeID(plist) == CFDictionaryGetTypeID()) {
		CFTypeRef v = CFDictionaryGetValue(plist, CFSTR("Partitions"));
		if (v != NULL && CFGetTypeID(v) == CFArrayGetTypeID()) result = CFRetain(v);
	}
	CFRelease(plist);
	return result;
}

// nk_encode_partitions is the inverse of nk_partitions.
static CFStringRef nk_encode_partitions(CFArrayRef partitions) {
	const void *keys[] = {CFSTR("Partitions")};
	const void *vals[] = {partitions};
	CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, vals, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDataRef data = CFPropertyListCreateData(NULL, dict, kCFPropertyListXMLFormat_v1_0, 0, NULL);
	CFRelease(dict);
	if (data == NULL) return NULL;
	CFIndex len = CFDataGetLength(data);
	const UInt8 *p = CFDataGetBytePtr(data);
	char *hex = malloc((size_t)len * 2 + 1);
	if (hex == NULL) { CFRelease(data); return NULL; }
	for (CFIndex i = 0; i < len; i++) snprintf(hex + 2 * i, 3, "%02x", p[i]);
	CFRelease(data);
	CFStringRef s = CFStringCreateWithCString(NULL, hex, kCFStringEncodingUTF8);
	free(hex);
	return s;
}

static OSStatus nk_find_item(const char *kcPath, const char *svc, const char *acct, SecKeychainRef *kc, SecKeychainItemRef *item) {
	OSStatus s = SecKeychainOpen(kcPath, kc);
	if (s != errSecSuccess) return s;
	// No data is requested, so finding the item never prompts.
	s = SecKeychainFindGenericPassword(*kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, NULL, NULL, item);
	if (s != errSecSuccess) CFRelease(*kc);
	return s;
}

// nk_partition_status sets *missing when the item restricts access to a
// partition list that doesn't contain pid. Items without a partition list
// aren't restricted, so they are never missing it.
static OSStatus nk_partition_status(const char *kcPath, const char *svc, const char *acct, const char *pid, int *missing) {
	SecKeychainRef kc;
	SecKeychainItemRef item;
	*missing = 0;
	OSStatus s = nk_find_item(kcPath, svc, acct, &kc, &item);
	if (s != errSecSuccess) return s;
	SecAccessRef access = NULL;
	s = SecKeychainItemCopyAccess(item, &access);
	CFRelease(item);
	CFRelease(kc);
	if (s != errSecSuccess) return s;

	CFStringRef want = CFStringCreateWithCString(NULL, pid, kCFStringEncodingUTF8);
	CFArrayRef acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationPartitionID);
	if (acls != NULL) {
		for (CFIndex i = 0; i < CFArrayGetCount(acls); i++) {
			CFArrayRef apps = NULL;
			CFStringRef desc = NULL;
			SecKeychainPromptSelector sel;
			if (SecACLCopyContents((SecACLRef)CFArrayGetValueAtIndex(acls, i), &apps, &desc, &sel) != errSecSuccess) continue;
			CFArrayRef parts = desc ? nk_partitions(desc) : NULL;
			if (parts != NULL) {
				if (!CFArrayContainsValue(parts, CFRangeMake(0, CFArrayGetCount(parts)), want)) *missing = 1;
				CFRelease(parts);
			}
			if (apps) CFRelease(apps);
			if (desc) CFRelease(desc);
		}
		CFRelease(acls);
	}
	CFRelease(want);
	CFRelease(access);
	return errSecSuccess;
}

// nk_add_partition appends pid to the item's partition list. Changing an
// item's access needs the keychain password.
static OSStatus nk_add_partition(const char *kcPath, const char *svc, const char *acct, const char *pid, const void *pw, UInt32 pwLen) {
	SecKeychainRef kc;
	SecKeychainItemRef item;
	OSStatus s = nk_find_item(kcPath, svc, acct, &kc, &item);
	if (s != errSecSuccess) return s;
	SecAccessRef access = NULL;
	s = SecKeychainItemCopyAccess(item, &access);
	if (s != errSecSuccess) { CFRelease(item); CFRelease(kc); return s; }

	CFStringRef want = CFStringCreateWithCString(NULL, pid, kCFStringEncodingUTF8);
	int changed = 0;
	CFArrayRef acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationPartitionID);
	if (acls != NULL) {
		for (CFIndex i = 0; i < CFArrayGetCount(acls); i++) {
			SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
			CFArrayRef apps = NULL;
			CFStringRef desc = NULL;
			SecKeychainPromptSelector sel;
			if (SecACLCopyContents(acl, &apps, &desc, &sel) != errSecSuccess) continue;
			CFArrayRef parts = desc ? nk_partitions(desc) : NULL;
			if (parts != NULL && !CFArrayContainsValue(parts, CFRangeMake(0, CFArrayGetCount(parts)), want)) {
				CFMutableArrayRef next = CFArrayCreateMutableCopy(NULL, 0, parts);
				CFArrayAppendValue(next, want);
				CFStringRef encoded = nk_encode_partitions(next);
				CFRelease(next);
				if (encoded == NULL) {
					s = errSecAllocate;
				} else {
					s = SecACLSetContents(acl, apps, encoded, sel);
					CFRelease(encoded);
					if (s == errSecSuccess) changed = 1;
				}
			}
			if (parts) CFRelease(parts);
			if (apps) CFRelease(apps);
			if (desc) CFRelease(desc);
			if (s != errSecSuccess) break;
		}
		CFRelease(acls);
	}
	CFRelease(want);
	if (s == errSecSuccess && changed) s = SecKeychainItemSetAccessWithPassword(item, access, pwLen, pw);
	CFRelease(access);
	CFRelease(item);
	CFRelease(kc);
	return s;
}

// nk_login_password reads a generic password from the default keychain
// search list (the login keychain). The caller frees *data with
// SecKeychainItemFreeContent.
static OSStatus nk_login_password(const char *svc, const char *acct, void **data, UInt32 *len) {
	return SecKeychainFindGenericPassword(NULL, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, len, data, NULL);
}

// nk_read_noninteractive reads an item's data with user interaction turned
// off, so access that would prompt fails with errSecInteractionNotAllowed.
static OSStatus nk_read_noninteractive(const char *kcPath, const char *svc, const char *acct) {
	SecKeychainRef kc;
	OSStatus s = SecKeychainOpen(kcPath, &kc);
	if (s != errSecSuccess) return s;
	Boolean prev = true;
	SecKeychainGetUserInteractionAllowed(&prev);
	SecKeychainSetUserInteractionAllowed(false);
	void *data = NULL;
	UInt32 len = 0;
	s = SecKeychainFindGenericPassword(kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, &len, &data, NULL);
	SecKeychainSetUserInteractionAllowed(prev);
	if (data != NULL) {
		memset(data, 0, len);
		SecKeychainItemFreeContent(NULL, data);
	}
	CFRelease(kc);
	return s;
}
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/nokey-ai/nokey/internal/sensitive"
)

// osStatusError describes a Security framework result code.
func osStatusError(op string, s C.OSStatus) error {
	msg := C.SecCopyErrorMessageString(s, nil)
	if msg == 0 {
		return fmt.Errorf("%s: OSStatus %d", op, int(s))
	}
	defer C.CFRelease(C.CFTypeRef(msg))
	var buf [256]C.char
	C.CFStringGetCString(msg, &buf[0], C.CFIndex(len(buf)), C.kCFStringEncodingUTF8)
	return fmt.Errorf("%s: %s (%d)", op, C.GoString(&buf[0]), int(s))
}

// runningBuildPartition returns the partition ID macOS assigns to the
// running binary, and whether the binary is certificate-signed.
func runningBuildPartition() (string, bool, error) {
	var out [41]C.char
	var hasCert C.int
	if s := C.nk_self_cdhash(&out[0], &hasCert); s != C.errSecSuccess {
		return "", false, osStatusError("read code signature", s)
	}
	return "cdhash:" + C.GoString(&out[0]), hasCert != 0, nil
}

func partitionMissing(keychainPath, service, account, partition string) (bool, error) {
	cPath, cSvc, cAcct, cPid := C.CString(keychainPath), C.CString(service), C.CString(account), C.CString(partition)
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cSvc))
	defer C.free(unsafe.Pointer(cAcct))
	defer C.free(unsafe.Pointer(cPid))
	var missing C.int
	if s := C.nk_partition_status(cPath, cSvc, cAcct, cPid, &missing); s != C.errSecSuccess {
		return false, osStatusError("read access for "+account, s)
	}
	return missing != 0, nil
}

func addPartition(keychainPath, service, account, partition string, password []byte) error {
	cPath, cSvc, cAcct, cPid := C.CString(keychainPath), C.CString(service), C.CString(account), C.CString(partition)
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cSvc))
	defer C.free(unsafe.Pointer(cAcct))
	defer C.free(unsafe.Pointer(cPid))
	// Copy into C memory so the password never moves with the Go heap, and
	// zero it before freeing.
	cPw := C.CBytes(password)
	defer func() {
		C.memset(cPw, 0, C.size_t(len(password)))
		C.free(cPw)
	}()
	if s := C.nk_add_partition(cPath, cSvc, cAcct, cPid, cPw, C.UInt32(len(password))); s != C.errSecSuccess {
		return osStatusError("update access for "+account, s)
	}
	return nil
}

// touchIDPassphrase reads the dedicated keychain's passphrase that
// byteness/keyring stores in the login keychain for Touch ID unlock.
func touchIDPassphrase(service string) ([]byte, error) {
	cSvc, cAcct := C.CString(service), C.CString(TouchIDAccount)
	defer C.free(unsafe.Pointer(cSvc))
	defer C.free(unsafe.Pointer(cAcct))
	var data unsafe.Pointer
	var n C.UInt32
	if s := C.nk_login_password(cSvc, cAcct, &data, &n); s != C.errSecSuccess {
		return nil, osStatusError("read Touch ID passphrase", s)
	}
	defer C.SecKeychainItemFreeContent(nil, data)
	defer C.memset(data, 0, C.size_t(n))
	return C.GoBytes(data, C.int(n)), nil
}

// trustRunningBuild lets the running nokey build read the given items in a
// dedicated keychain without prompting.
//
// Each item records the code hashes of the builds that may read it (its
// partition list). A certificate-signed binary that isn't signed by Apple
// is identified by its code hash, so every upgrade makes macOS ask for the
// keychain password once per item. This adds the running build to each
// item that lacks it, using the passphrase stored for Touch ID unlock.
//
// Only the partition list changes. Each item's list of trusted
// applications still requires nokey's signing certificate, so a binary
// that isn't signed with it gains nothing from being added here, and
// ad-hoc builds are skipped. It returns how many items were updated.
func trustRunningBuild(keychainPath, service string, accounts []string) (int, error) {
	partition, signed, err := runningBuildPartition()
	if err != nil || !signed {
		return 0, err
	}
	return trustBuild(keychainPath, service, accounts, partition, touchIDPassphrase)
}

// trustBuild adds partition to each item that lacks it, fetching the
// keychain password only when there is something to change.
func trustBuild(keychainPath, service string, accounts []string, partition string, passphrase func(service string) ([]byte, error)) (int, error) {
	var missing []string
	for _, acct := range accounts {
		m, err := partitionMissing(keychainPath, service, acct, partition)
		if err != nil {
			return 0, err
		}
		if m {
			missing = append(missing, acct)
		}
	}
	if len(missing) == 0 {
		return 0, nil
	}

	pw, err := passphrase(service)
	if err != nil {
		// Without Touch ID set up there is no stored passphrase, and macOS
		// prompts per item as before.
		return 0, nil
	}
	defer sensitive.ClearBytes(pw)
	for i, acct := range missing {
		if err := addPartition(keychainPath, service, acct, partition, pw); err != nil {
			return i, err
		}
	}
	fmt.Fprintf(os.Stderr, "nokey: allowed this build to read %d keychain item(s) without prompting\n", len(missing))
	return len(missing), nil
}

// readWithoutPrompt reports whether the running binary can read the item's
// data without macOS asking the user. Tests use it to observe partition
// lists taking effect.
func readWithoutPrompt(keychainPath, service, account string) error {
	cPath, cSvc, cAcct := C.CString(keychainPath), C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cSvc))
	defer C.free(unsafe.Pointer(cAcct))
	if s := C.nk_read_noninteractive(cPath, cSvc, cAcct); s != C.errSecSuccess {
		return osStatusError("read "+account, s)
	}
	return nil
}
