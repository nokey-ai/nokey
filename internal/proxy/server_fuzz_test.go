package proxy

import (
	"net"
	"strings"
	"testing"
)

// FuzzValidateListenAddr checks that every address ValidateListenAddr
// accepts is one the net package also reads as loopback. The proxy holds
// plaintext secrets, so the two disagreeing on any input would let it bind
// somewhere reachable from off the machine.
func FuzzValidateListenAddr(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1:0", "localhost:8080", "LOCALHOST:1", "[::1]:0",
		"[::ffff:127.0.0.1]:0", "[::1%lo0]:0", "127.255.255.254:9",
		":8080", "0.0.0.0:8080", "[::]:0", "10.0.0.1:80", "[::ffff:10.0.0.1]:0",
		"127.1:0", "0x7f.0.0.1:0", "localhost.:0", "127.0.0.1", "[127.0.0.1]:0",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, addr string) {
		if ValidateListenAddr(addr) != nil {
			return
		}

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("accepted %q, which net.SplitHostPort rejects: %v", addr, err)
		}
		if strings.EqualFold(host, "localhost") {
			return
		}

		// Anything else accepted must be an IP literal, so this resolves
		// without DNS.
		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			// An unusable port; Listen would fail before binding.
			return
		}
		if !tcpAddr.IP.IsLoopback() {
			t.Fatalf("accepted %q, which net resolves to non-loopback %s", addr, tcpAddr.IP)
		}
	})
}
