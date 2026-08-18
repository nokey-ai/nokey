package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/sensitive"
)

// AuditFunc is called after each proxied request with operation details.
type AuditFunc func(operation, host, secrets string, ok bool, errMsg string)

// Server is a local HTTP/HTTPS forward proxy that injects secrets into
// request headers based on policy proxy rules.
type Server struct {
	ca             *CA
	rules          []policy.ProxyRule
	secrets        map[string]string
	pol            *policy.Policy
	auditFn        AuditFunc
	listener       net.Listener
	server         *http.Server
	certCache      sync.Map // host → *tls.Certificate
	mu             sync.Mutex
	running        bool
	blockUnmatched bool              // if true, reject requests to hosts with no matching proxy rule
	transport      http.RoundTripper // forward transport; nil falls back to http.DefaultTransport
	// inflight tracks hijacked CONNECT goroutines. http.Server.Shutdown
	// does not wait on hijacked connections, so Stop uses this to drain
	// them before clearing s.secrets — otherwise an in-flight request
	// loop in handleConnect would read a nil secrets map mid-RoundTrip.
	inflight      sync.WaitGroup
	inflightConns sync.Map // *tls.Conn → struct{}; force-closed on Stop to unblock ReadRequest
}

// SetTransport overrides the round-tripper used to forward proxied
// requests upstream. Intended for tests; production callers can rely on
// the default (http.DefaultTransport).
func (s *Server) SetTransport(rt http.RoundTripper) {
	s.transport = rt
}

// forwardTransport returns the configured transport or the package
// default. Resolving once per request avoids reading http.DefaultTransport
// concurrently with anything else that might write it (e.g. legacy tests).
func (s *Server) forwardTransport() http.RoundTripper {
	if s.transport != nil {
		return s.transport
	}
	return http.DefaultTransport
}

// NewServer creates a new proxy server. Secrets are held in memory for the
// lifetime of the server (fetched once at startup).
func NewServer(ca *CA, rules []policy.ProxyRule, secrets map[string]string, pol *policy.Policy, auditFn AuditFunc) *Server {
	return &Server{
		ca:      ca,
		rules:   rules,
		secrets: secrets,
		pol:     pol,
		auditFn: auditFn,
	}
}

// SetBlockUnmatched enables egress filtering: requests to hosts with no
// matching proxy rule are rejected with 403 instead of being forwarded.
func (s *Server) SetBlockUnmatched(block bool) {
	s.blockUnmatched = block
}

// Start begins listening on addr (e.g. "127.0.0.1:0") and returns the actual
// address. addr must be on the loopback interface. The caller must eventually
// call Stop.
func (s *Server) Start(addr string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return s.listener.Addr().String(), nil
	}

	if addr == "" {
		addr = "127.0.0.1:0"
	}

	// Check before binding: a non-loopback bind must never happen, not even
	// for the microseconds between Listen and a post-hoc check.
	if err := ValidateListenAddr(addr); err != nil {
		return "", err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to listen: %w", err)
	}

	// Authoritative check on what we actually got. ValidateListenAddr
	// accepts the hostname "localhost", which the resolver — not us — maps to
	// an address, so confirm the bound address really is loopback.
	if err := verifyLoopbackListener(ln); err != nil {
		_ = ln.Close()
		return "", err
	}

	s.listener = ln
	s.server = &http.Server{
		Handler:      s,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	s.running = true

	go func() {
		_ = s.server.Serve(ln)
	}()

	return ln.Addr().String(), nil
}

// loopbackOnlyReason explains why the proxy refuses non-loopback binds. The
// proxy holds plaintext secrets and injects them into any request matching a
// rule, so anyone who can reach it can spend the user's credentials.
const loopbackOnlyReason = "the proxy injects your secrets into matching requests, so it only listens on loopback (127.0.0.1, ::1, or localhost)"

// ValidateListenAddr rejects listen addresses that are not on the loopback
// interface: the unspecified address (":8080", "0.0.0.0:8080", "[::]:8080"),
// routable literals, and hostnames other than "localhost".
func ValidateListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}

	// An empty host means every interface, e.g. ":8080".
	if host == "" {
		return fmt.Errorf("refusing to listen on %q: an empty host binds every interface — %s", addr, loopbackOnlyReason)
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		// Not a literal, so it is a hostname. "localhost" is the one name
		// conventionally guaranteed to be loopback; anything else can resolve
		// off-host, and could resolve differently later.
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		return fmt.Errorf("refusing to listen on %q: %q is not a loopback address — %s", addr, host, loopbackOnlyReason)
	}

	// Unmap ::ffff:127.0.0.1 and friends so an IPv4-mapped IPv6 literal is
	// judged on the IPv4 address it actually carries.
	if ip.Is4In6() {
		ip = ip.Unmap()
	}

	if !ip.IsLoopback() {
		return fmt.Errorf("refusing to listen on %q: %s is not a loopback address — %s", addr, ip, loopbackOnlyReason)
	}

	return nil
}

// verifyLoopbackListener confirms a bound listener is on loopback, catching
// any resolution that produced a routable address despite ValidateListenAddr.
func verifyLoopbackListener(ln net.Listener) error {
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("refusing to serve on %s: not a TCP listener — %s", ln.Addr(), loopbackOnlyReason)
	}
	if !tcpAddr.IP.IsLoopback() {
		return fmt.Errorf("refusing to serve on %s: bound to a non-loopback address — %s", tcpAddr, loopbackOnlyReason)
	}
	return nil
}

// Stop gracefully shuts down the proxy server.
// Order matters: shut down the http.Server first to refuse new
// connections, wait for in-flight hijacked CONNECT goroutines to
// finish, and only then clear the secrets map. Reversing this risks
// in-flight goroutines reading a nil map mid-request.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	srv := s.server
	s.mu.Unlock()

	shutdownErr := srv.Shutdown(ctx)

	// Force-close hijacked TLS conns so blocked ReadRequest calls
	// inside handleConnect return immediately; otherwise idle clients
	// (between requests on the same tunnel) would hang inflight.Wait.
	s.inflightConns.Range(func(k, _ any) bool {
		_ = k.(*tls.Conn).Close()
		return true
	})
	s.inflight.Wait()

	s.mu.Lock()
	sensitive.ClearMap(s.secrets)
	s.secrets = nil
	s.mu.Unlock()

	return shutdownErr
}

// Addr returns the proxy's listen address, or empty if not running.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// ServeHTTP dispatches proxy requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
	} else {
		s.handleHTTP(w, r)
	}
}

// handleHTTP forwards plain HTTP requests, injecting headers where rules match.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)
	matched := MatchRules(host, s.rules)

	// Egress filtering: block requests to hosts with no matching rule.
	if len(matched) == 0 && s.blockUnmatched {
		s.audit("proxy:http:blocked", host, nil, false, "no matching proxy rule (egress blocked)")
		http.Error(w, "nokey proxy: egress blocked — no proxy rule matches this host", http.StatusForbidden)
		return
	}

	secretNames := CollectSecretNames(matched)

	// Approval check: proxy runs outside MCP session context, so if approval
	// is required we deny with a clear error.
	if len(matched) > 0 && s.pol.ProxyRequiresApproval(host, secretNames) {
		s.audit("proxy:http", host, secretNames, false, "approval required — set approval: never on this proxy rule")
		http.Error(w, "nokey proxy: approval required for this host — set approval: never on the proxy rule", http.StatusForbidden)
		return
	}

	// Inject headers from matching rules.
	for _, rule := range matched {
		headers, err := ResolveHeaders(rule, s.secrets)
		if err != nil {
			s.audit("proxy:http", host, secretNames, false, err.Error())
			http.Error(w, fmt.Sprintf("nokey proxy: %s", err), http.StatusBadGateway)
			return
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
	}

	// Forward the request.
	r.RequestURI = ""
	resp, err := s.forwardTransport().RoundTrip(r)
	if err != nil {
		s.audit("proxy:http", host, secretNames, false, err.Error())
		http.Error(w, fmt.Sprintf("nokey proxy: upstream error: %s", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	s.audit("proxy:http", host, secretNames, true, "")

	// Copy response.
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleConnect handles the HTTPS CONNECT method, performing MITM with the
// local CA to inject headers into the decrypted request.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	host := stripPort(hostPort)

	// Egress filtering: reject CONNECT to hosts with no matching rule before
	// establishing the tunnel.
	if s.blockUnmatched && len(MatchRules(host, s.rules)) == 0 {
		s.audit("proxy:https:blocked", host, nil, false, "no matching proxy rule (egress blocked)")
		http.Error(w, "nokey proxy: egress blocked — no proxy rule matches this host", http.StatusForbidden)
		return
	}

	// Hijack the connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Register the hijacked goroutine so Stop can wait for it to drain
	// before clearing s.secrets.
	s.inflight.Add(1)
	defer s.inflight.Done()
	defer clientConn.Close()

	// Clear deadlines for the tunneled connection
	_ = clientConn.SetDeadline(time.Time{})

	// Send 200 Connection Established.
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Get or create cert for host.
	cert, err := s.getOrCreateCert(host)
	if err != nil {
		return
	}

	// TLS handshake with client.
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"}, // Force HTTP/1.1
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	// Validate the TLS SNI matches the CONNECT-line host. Without this,
	// a client could CONNECT to an allow-listed host (and get policy rules
	// + secret injection bound to it) but then negotiate TLS for any
	// other host. RFC 6066 forbids SNI for literal IPs, so we only
	// enforce the check when the CONNECT host is a DNS name. Missing SNI
	// on a DNS host is rejected — every modern HTTPS client sends it,
	// and silence would let a hostile client bypass this check.
	if net.ParseIP(host) == nil {
		sni := tlsConn.ConnectionState().ServerName
		if sni == "" || !strings.EqualFold(sni, host) {
			s.audit("proxy:https:blocked", host, nil, false, fmt.Sprintf("SNI %q does not match CONNECT host %q", sni, host))
			return
		}
	}

	// Track the live TLS conn so Stop can force-close it to unblock the
	// read loop below.
	s.inflightConns.Store(tlsConn, struct{}{})
	defer s.inflightConns.Delete(tlsConn)

	// Read requests from the TLS connection.
	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return // Client closed connection or read error.
		}

		// Validate the inner request Host matches the CONNECT-line host.
		// Even with SNI pinned, the inner HTTP/1.1 request can carry an
		// arbitrary Host header — without this check a client could
		// tunnel CONNECT example.com:443 and then send GET /
		// Host: api.attacker.com and have api.attacker.com's secrets
		// injected if both rules matched.
		if !strings.EqualFold(stripPort(req.Host), host) {
			s.audit("proxy:https:blocked", host, nil, false, fmt.Sprintf("inner Host %q does not match CONNECT host %q", req.Host, host))
			resp := &http.Response{
				StatusCode: http.StatusMisdirectedRequest,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("nokey proxy: inner Host header does not match CONNECT host")),
			}
			resp.Header.Set("Content-Type", "text/plain")
			_ = resp.Write(tlsConn)
			return
		}

		// Set the full URL for the upstream request.
		req.URL.Scheme = "https"
		req.URL.Host = hostPort
		req.RequestURI = ""

		matched := MatchRules(host, s.rules)
		secretNames := CollectSecretNames(matched)

		// Approval check.
		if len(matched) > 0 && s.pol.ProxyRequiresApproval(host, secretNames) {
			s.audit("proxy:https", host, secretNames, false, "approval required — set approval: never on this proxy rule")
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("nokey proxy: approval required for this host — set approval: never on the proxy rule")),
			}
			resp.Header.Set("Content-Type", "text/plain")
			_ = resp.Write(tlsConn)
			continue
		}

		// Inject headers. If any rule fails to resolve, surface 502 to
		// the client and skip the upstream RoundTrip — otherwise we
		// would still send the request without the intended header.
		headerErr := false
		for _, rule := range matched {
			headers, err := ResolveHeaders(rule, s.secrets)
			if err != nil {
				s.audit("proxy:https", host, secretNames, false, err.Error())
				resp := &http.Response{
					StatusCode: http.StatusBadGateway,
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("nokey proxy: %s", err))),
				}
				resp.Header.Set("Content-Type", "text/plain")
				_ = resp.Write(tlsConn)
				headerErr = true
				break
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
		if headerErr {
			continue
		}

		// Forward upstream.
		resp, err := s.forwardTransport().RoundTrip(req)
		if err != nil {
			s.audit("proxy:https", host, secretNames, false, err.Error())
			errResp := &http.Response{
				StatusCode: http.StatusBadGateway,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("nokey proxy: upstream error: %s", err))),
			}
			errResp.Header.Set("Content-Type", "text/plain")
			_ = errResp.Write(tlsConn)
			continue
		}

		s.audit("proxy:https", host, secretNames, true, "")
		_ = resp.Write(tlsConn)
		_ = resp.Body.Close()
	}
}

func (s *Server) getOrCreateCert(host string) (*tls.Certificate, error) {
	if cached, ok := s.certCache.Load(host); ok {
		return cached.(*tls.Certificate), nil
	}
	cert, err := s.ca.GenerateHostCert(host)
	if err != nil {
		return nil, err
	}
	s.certCache.Store(host, cert)
	return cert, nil
}

func (s *Server) audit(op, host string, secretNames []string, ok bool, errMsg string) {
	if s.auditFn == nil {
		return
	}
	s.auditFn(op, host, strings.Join(secretNames, ","), ok, errMsg)
}

// copyHeaders copies response headers to the proxy response writer.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// stripPort removes the port from a host:port string.
func stripPort(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort // No port.
	}
	return host
}
