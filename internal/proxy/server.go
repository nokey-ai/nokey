package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
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
	blockUnmatched bool // if true, reject requests to hosts with no matching proxy rule
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
// address. The caller must eventually call Stop.
func (s *Server) Start(addr string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return s.listener.Addr().String(), nil
	}

	if addr == "" {
		addr = "127.0.0.1:0"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to listen: %w", err)
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

// Stop gracefully shuts down the proxy server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}
	s.running = false
	sensitive.ClearMap(s.secrets)
	s.secrets = nil
	return s.server.Shutdown(ctx)
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
	resp, err := http.DefaultTransport.RoundTrip(r)
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

	// Read requests from the TLS connection.
	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return // Client closed connection or read error.
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

		// Inject headers.
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
				continue
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}

		// Forward upstream.
		resp, err := http.DefaultTransport.RoundTrip(req)
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
