package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
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

	// The proxy's CONNECT handler dials the upstream using http.DefaultTransport.
	// Override it to trust the test server's self-signed cert.
	origTransport := http.DefaultTransport
	upstreamPool := x509.NewCertPool()
	upstreamCert, err := x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse upstream cert: %v", err)
	}
	upstreamPool.AddCert(upstreamCert)

	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    upstreamPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

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

type auditEntry struct {
	op      string
	host    string
	secrets string
	ok      bool
	errMsg  string
}
