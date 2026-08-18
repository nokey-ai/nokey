package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nokey-ai/nokey/internal/policy"
)

// newTestCA creates a CA in a temp dir for testing.
func newTestCA(t *testing.T) *CA {
	t.Helper()
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	return ca
}

func proxyTransport(proxyAddr string) *http.Transport {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
}

func TestHTTPProxyForwardsAndInjectsHeaders(t *testing.T) {
	// Upstream server that echoes back request headers.
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	// Extract upstream host.
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:   []string{stripPort(upstreamHost)},
			Headers: map[string]string{"Authorization": "Bearer $TOKEN"},
			Secrets: []string{"TOKEN"},
		},
	}
	secrets := map[string]string{"TOKEN": "sk-test-123"}

	var audits []auditEntry
	var auditMu sync.Mutex
	auditFn := func(op, host, secrets string, ok bool, errMsg string) {
		auditMu.Lock()
		defer auditMu.Unlock()
		audits = append(audits, auditEntry{op, host, secrets, ok, errMsg})
	}

	srv := NewServer(ca, rules, secrets, nil, auditFn)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client := &http.Client{Transport: proxyTransport(addr)}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}

	// Verify header was injected.
	if got := receivedHeaders.Get("Authorization"); got != "Bearer sk-test-123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer sk-test-123")
	}

	// Verify audit was called.
	auditMu.Lock()
	defer auditMu.Unlock()
	if len(audits) == 0 {
		t.Error("expected at least one audit entry")
	} else if !audits[0].ok {
		t.Errorf("audit entry ok = false, errMsg = %q", audits[0].errMsg)
	}
}

func TestHTTPProxyNoMatchPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("unexpected Authorization header: %s", auth)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:   []string{"other.example.com"},
			Headers: map[string]string{"Authorization": "Bearer $TOKEN"},
			Secrets: []string{"TOKEN"},
		},
	}
	secrets := map[string]string{"TOKEN": "sk-test-123"}

	srv := NewServer(ca, rules, secrets, nil, nil)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client := &http.Client{Transport: proxyTransport(addr)}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHTTPSConnectAndInject(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok-tls")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	host := stripPort(upstreamHost)

	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:   []string{host},
			Headers: map[string]string{"X-Api-Key": "$KEY"},
			Secrets: []string{"KEY"},
		},
	}
	secrets := map[string]string{"KEY": "secret-value"}

	var audits []auditEntry
	var auditMu sync.Mutex
	auditFn := func(op, host, secrets string, ok bool, errMsg string) {
		auditMu.Lock()
		defer auditMu.Unlock()
		audits = append(audits, auditEntry{op, host, secrets, ok, errMsg})
	}

	srv := NewServer(ca, rules, secrets, nil, auditFn)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	// The proxy's CONNECT handler dials the upstream using its configured
	// transport. Inject one that trusts the test server's self-signed cert.
	upstreamPool := x509.NewCertPool()
	upstreamCert, err := x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse upstream cert: %v", err)
	}
	upstreamPool.AddCert(upstreamCert)
	srv.SetTransport(&http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    upstreamPool,
			MinVersion: tls.VersionTLS12,
		},
	})

	// Client trusts the proxy CA for the MITM cert.
	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(ca.Cert)

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    proxyPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if string(body) != "ok-tls" {
		t.Errorf("body = %q, want %q", body, "ok-tls")
	}

	if got := receivedHeaders.Get("X-Api-Key"); got != "secret-value" {
		t.Errorf("X-Api-Key = %q, want %q", got, "secret-value")
	}

	auditMu.Lock()
	defer auditMu.Unlock()
	if len(audits) == 0 {
		t.Error("expected audit entry")
	}
}

func TestApprovalDeniesRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not reach upstream")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	host := stripPort(upstreamHost)

	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:    []string{host},
			Headers:  map[string]string{"Authorization": "Bearer $TOKEN"},
			Secrets:  []string{"TOKEN"},
			Approval: policy.ApprovalAlways,
		},
	}
	secrets := map[string]string{"TOKEN": "sk-123"}
	pol := &policy.Policy{
		Proxy: &policy.ProxyPolicy{
			Approval: policy.ApprovalAlways,
			Rules:    rules,
		},
	}

	srv := NewServer(ca, rules, secrets, pol, nil)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client := &http.Client{Transport: proxyTransport(addr)}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestGracefulShutdown(t *testing.T) {
	ca := newTestCA(t)
	srv := NewServer(ca, nil, nil, nil, nil)

	_, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("expected non-empty addr")
	}

	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Stop again should be a no-op.
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// TestStopDrainsInflightCONNECT verifies that Stop blocks until any
// hijacked CONNECT goroutine has exited. Without the drain, Stop would
// return while the read loop in handleConnect was still alive, and an
// in-flight RoundTrip could call ResolveHeaders against a nil secrets
// map (silently dropping secrets from the response).
func TestStopDrainsInflightCONNECT(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	host := stripPort(upstreamHost)

	ca := newTestCA(t)
	rules := []policy.ProxyRule{{
		Hosts:   []string{host},
		Headers: map[string]string{"X-Api-Key": "$KEY"},
		Secrets: []string{"KEY"},
	}}
	srv := NewServer(ca, rules, map[string]string{"KEY": "secret"}, nil, nil)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	upstreamPool := x509.NewCertPool()
	upstreamCert, err := x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse upstream cert: %v", err)
	}
	upstreamPool.AddCert(upstreamCert)
	srv.SetTransport(&http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: upstreamPool, MinVersion: tls.VersionTLS12},
	})

	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(ca.Cert)

	proxyURL, _ := url.Parse("http://" + addr)
	clientTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:    proxyPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: clientTransport}

	// Fire one request through the CONNECT tunnel. After the response,
	// the client keeps the tunnel open in its idle pool, so the
	// handleConnect goroutine returns to ReadRequest and blocks
	// indefinitely — that's the state we need Stop to drain.
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// Sanity check: the tunnel goroutine is still alive.
	srv.inflight.Add(0) // no-op, just for clarity
	if !inflightAlive(srv) {
		t.Fatal("expected an in-flight tunnel goroutine after request — test setup is wrong")
	}

	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// After Stop returns, the inflight goroutine must be gone — that's
	// the guarantee. Without the fix, Stop returns immediately and the
	// goroutine is still parked in ReadRequest.
	if inflightAlive(srv) {
		t.Fatal("inflight CONNECT goroutine still alive after Stop returned")
	}

	// Secrets must have been zeroed only after drain — verify they're nil
	// now (defense-in-depth that Stop actually completed cleanup).
	srv.mu.Lock()
	secretsAfter := srv.secrets
	srv.mu.Unlock()
	if secretsAfter != nil {
		t.Errorf("secrets not cleared after Stop: %v", secretsAfter)
	}

	clientTransport.CloseIdleConnections()
}

// inflightAlive reports whether any tunnel goroutine is currently
// tracked in s.inflightConns. Used by the drain test to assert the
// goroutine is gone after Stop returns.
func inflightAlive(s *Server) bool {
	alive := false
	s.inflightConns.Range(func(_, _ any) bool {
		alive = true
		return false
	})
	return alive
}

// TestCONNECTRejectsHostMismatch verifies that an inner request whose
// Host header differs from the CONNECT-line host is rejected with 421
// and no upstream RoundTrip fires. Without this check, a client could
// CONNECT to an allow-listed host and then tunnel requests for any
// other host, smuggling the allow-listed host's headers/secrets onto
// an unrelated origin.
func TestCONNECTRejectsHostMismatch(t *testing.T) {
	upstreamReached := false
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReached = true
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	host := stripPort(upstreamHost)

	ca := newTestCA(t)
	rules := []policy.ProxyRule{{
		Hosts:   []string{host},
		Headers: map[string]string{"X-Api-Key": "$KEY"},
		Secrets: []string{"KEY"},
	}}
	srv := NewServer(ca, rules, map[string]string{"KEY": "secret"}, nil, nil)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	upstreamPool := x509.NewCertPool()
	upstreamCert, err := x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse upstream cert: %v", err)
	}
	upstreamPool.AddCert(upstreamCert)
	srv.SetTransport(&http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: upstreamPool, MinVersion: tls.VersionTLS12},
	})

	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(ca.Cert)

	// Dial the proxy, CONNECT to the allow-listed upstream host:port,
	// complete TLS using upstream host as ServerName, then send an
	// inner request whose Host header is a different origin.
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer rawConn.Close()

	if _, err := fmt.Fprintf(rawConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamHost, upstreamHost); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	tlsClient := tls.Client(rawConn, &tls.Config{
		ServerName: host, // matches CONNECT host so SNI check passes
		RootCAs:    proxyPool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Smuggle a request with a different Host header.
	if _, err := fmt.Fprintf(tlsClient, "GET / HTTP/1.1\r\nHost: api.attacker.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write smuggled request: %v", err)
	}
	innerResp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("read smuggled response: %v", err)
	}
	defer innerResp.Body.Close()

	if innerResp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("smuggled request status = %d, want 421", innerResp.StatusCode)
	}
	if upstreamReached {
		t.Error("upstream was hit by smuggled request")
	}
}

func TestBlockUnmatchedHTTP(t *testing.T) {
	// Upstream should never be reached when egress is blocked.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not reach upstream")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:   []string{"allowed.example.com"},
			Headers: map[string]string{"Authorization": "Bearer $TOKEN"},
			Secrets: []string{"TOKEN"},
		},
	}
	secrets := map[string]string{"TOKEN": "sk-test-123"}

	srv := NewServer(ca, rules, secrets, nil, nil)
	srv.SetBlockUnmatched(true)

	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client := &http.Client{Transport: proxyTransport(addr)}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestBlockUnmatchedAllowsMatchedHost(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:   []string{stripPort(upstreamHost)},
			Headers: map[string]string{"Authorization": "Bearer $TOKEN"},
			Secrets: []string{"TOKEN"},
		},
	}
	secrets := map[string]string{"TOKEN": "sk-test-123"}

	srv := NewServer(ca, rules, secrets, nil, nil)
	srv.SetBlockUnmatched(true)

	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client := &http.Client{Transport: proxyTransport(addr)}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
	if got := receivedHeaders.Get("Authorization"); got != "Bearer sk-test-123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer sk-test-123")
	}
}

func TestBlockUnmatchedCONNECT(t *testing.T) {
	// Try to CONNECT to a host with no matching rule. The proxy should
	// reject with 403 before establishing the tunnel.
	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:   []string{"allowed.example.com"},
			Headers: map[string]string{"Authorization": "Bearer $TOKEN"},
			Secrets: []string{"TOKEN"},
		},
	}

	srv := NewServer(ca, rules, map[string]string{"TOKEN": "sk-123"}, nil, nil)
	srv.SetBlockUnmatched(true)

	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	// CONNECT to an unmatched host via the proxy.
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Use HTTPS to trigger a CONNECT request.
	_, err = client.Get("https://evil.example.com/steal")
	if err == nil {
		t.Fatal("expected error for blocked CONNECT, got nil")
	}
	// The error message should indicate the request was forbidden.
	errStr := err.Error()
	if !strings.Contains(errStr, "403") && !strings.Contains(errStr, "Forbidden") {
		t.Errorf("expected 403/Forbidden in error, got: %v", err)
	}
}

func TestStartAlreadyRunning(t *testing.T) {
	ca := newTestCA(t)
	srv := NewServer(ca, nil, nil, nil, nil)
	addr1, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	// Start again should return same address.
	addr2, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if addr1 != addr2 {
		t.Errorf("second Start returned different addr: %s vs %s", addr1, addr2)
	}
}

// --- loopback-only binding ---

func TestValidateLoopbackAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"ipv4 loopback", "127.0.0.1:0", false},
		{"ipv4 loopback non-zero port", "127.0.0.1:8080", false},
		{"ipv4 loopback alternate", "127.0.0.53:8080", false},
		{"ipv6 loopback", "[::1]:0", false},
		{"localhost", "localhost:0", false},
		{"localhost mixed case", "LocalHost:8080", false},
		{"ipv4-mapped ipv6 loopback", "[::ffff:127.0.0.1]:8080", false},

		{"ipv4 unspecified", "0.0.0.0:8080", true},
		{"ipv6 unspecified", "[::]:8080", true},
		{"empty host", ":8080", true},
		{"private lan address", "192.168.1.10:8080", true},
		{"public address", "203.0.113.5:8080", true},
		{"ipv4-mapped ipv6 unspecified", "[::ffff:0.0.0.0]:80", true},
		{"ipv4-mapped ipv6 routable", "[::ffff:192.168.1.10]:80", true},
		{"routable ipv6", "[2001:db8::1]:8080", true},
		{"hostname", "evil.example:80", true},
		{"missing port", "127.0.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateListenAddr(tt.addr)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateListenAddr(%q) = nil, want error", tt.addr)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateListenAddr(%q) = %v, want nil", tt.addr, err)
			}
		})
	}
}

// TestStartRejectsNonLoopback is the regression test for the proxy being
// bindable to the network: the MCP start_proxy tool takes addr straight from
// the model, so a compromised agent could have exposed every injected secret
// to anyone who could reach the port.
func TestStartRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "[::]:0", ":0", "[::ffff:0.0.0.0]:0"} {
		t.Run(addr, func(t *testing.T) {
			ca := newTestCA(t)
			srv := NewServer(ca, nil, nil, nil, nil)

			got, err := srv.Start(addr)
			if err == nil {
				_ = srv.Stop(context.Background())
				t.Fatalf("Start(%q) = %q, want error", addr, got)
			}
			if !strings.Contains(err.Error(), "loopback") {
				t.Errorf("Start(%q) error = %v, want it to mention loopback", addr, err)
			}
			if srv.Addr() != "" {
				t.Errorf("Addr() = %q after refused Start, want empty", srv.Addr())
			}
		})
	}
}

func TestStartAcceptsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "localhost:0"} {
		t.Run(addr, func(t *testing.T) {
			ca := newTestCA(t)
			srv := NewServer(ca, nil, nil, nil, nil)

			got, err := srv.Start(addr)
			if err != nil {
				t.Fatalf("Start(%q): %v", addr, err)
			}
			defer func() { _ = srv.Stop(context.Background()) }()

			host, _, err := net.SplitHostPort(got)
			if err != nil {
				t.Fatalf("SplitHostPort(%q): %v", got, err)
			}
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				t.Errorf("Start(%q) bound to %q, want a loopback address", addr, got)
			}
		})
	}
}

func TestVerifyLoopbackListener(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot bind wildcard address: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if err := verifyLoopbackListener(ln); err == nil {
		t.Error("verifyLoopbackListener should reject a wildcard-bound listener")
	}

	loopback, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	defer func() { _ = loopback.Close() }()

	if err := verifyLoopbackListener(loopback); err != nil {
		t.Errorf("verifyLoopbackListener rejected a loopback listener: %v", err)
	}
}

func TestAddrNotRunning(t *testing.T) {
	ca := newTestCA(t)
	srv := NewServer(ca, nil, nil, nil, nil)
	if addr := srv.Addr(); addr != "" {
		t.Errorf("Addr before Start should be empty, got %q", addr)
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"127.0.0.1:8080", "127.0.0.1"},
	}
	for _, tt := range tests {
		if got := stripPort(tt.input); got != tt.want {
			t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCopyHeaders(t *testing.T) {
	src := http.Header{
		"Content-Type": []string{"application/json"},
		"X-Custom":     []string{"val1", "val2"},
	}
	dst := make(http.Header)
	copyHeaders(dst, src)
	if got := dst.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
	if got := dst.Values("X-Custom"); len(got) != 2 {
		t.Errorf("X-Custom values = %v, want 2 values", got)
	}
}

func TestHTTPProxyHeaderResolveError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:   []string{stripPort(upstreamHost)},
			Headers: map[string]string{"Authorization": "Bearer $MISSING_SECRET"},
			Secrets: []string{"MISSING_SECRET"},
		},
	}
	// secrets map is missing the required secret.
	secrets := map[string]string{}

	srv := NewServer(ca, rules, secrets, nil, nil)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client := &http.Client{Transport: proxyTransport(addr)}
	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

func TestGetOrCreateCert_Cache(t *testing.T) {
	ca := newTestCA(t)
	srv := NewServer(ca, nil, nil, nil, nil)

	cert1, err := srv.getOrCreateCert("example.com")
	if err != nil {
		t.Fatalf("first getOrCreateCert: %v", err)
	}
	cert2, err := srv.getOrCreateCert("example.com")
	if err != nil {
		t.Fatalf("second getOrCreateCert: %v", err)
	}
	if cert1 != cert2 {
		t.Error("expected same cert pointer from cache")
	}
}

func TestStartDefaultAddr(t *testing.T) {
	ca := newTestCA(t)
	srv := NewServer(ca, nil, nil, nil, nil)
	addr, err := srv.Start("")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()
	if addr == "" {
		t.Error("expected non-empty address")
	}
}

func TestHTTPSConnectApprovalDenied(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not reach upstream")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	host := stripPort(upstreamHost)

	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:    []string{host},
			Headers:  map[string]string{"Authorization": "Bearer $TOKEN"},
			Secrets:  []string{"TOKEN"},
			Approval: policy.ApprovalAlways,
		},
	}
	secrets := map[string]string{"TOKEN": "sk-123"}
	pol := &policy.Policy{
		Proxy: &policy.ProxyPolicy{
			Approval: policy.ApprovalAlways,
			Rules:    rules,
		},
	}

	srv := NewServer(ca, rules, secrets, pol, nil)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	// Inject a transport that trusts the upstream TLS cert.
	upstreamPool := x509.NewCertPool()
	upstreamCert, err := x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse upstream cert: %v", err)
	}
	upstreamPool.AddCert(upstreamCert)
	srv.SetTransport(&http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    upstreamPool,
			MinVersion: tls.VersionTLS12,
		},
	})

	// Client trusts the proxy CA for the MITM cert.
	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(ca.Cert)

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    proxyPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHTTPSConnectHeaderResolveError(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach upstream")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")
	host := stripPort(upstreamHost)

	ca := newTestCA(t)
	rules := []policy.ProxyRule{
		{
			Hosts:   []string{host},
			Headers: map[string]string{"Authorization": "Bearer $MISSING_SECRET"},
			Secrets: []string{"MISSING_SECRET"},
		},
	}
	// Secrets map is empty — resolve will fail.
	secrets := map[string]string{}

	srv := NewServer(ca, rules, secrets, nil, nil)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	// Inject a transport that trusts the upstream TLS cert.
	upstreamPool := x509.NewCertPool()
	upstreamCert, err := x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse upstream cert: %v", err)
	}
	upstreamPool.AddCert(upstreamCert)
	srv.SetTransport(&http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    upstreamPool,
			MinVersion: tls.VersionTLS12,
		},
	})

	// Client trusts the proxy CA for the MITM cert.
	proxyPool := x509.NewCertPool()
	proxyPool.AddCert(ca.Cert)

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    proxyPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

type auditEntry struct {
	op      string
	host    string
	secrets string
	ok      bool
	errMsg  string
}
