---
type: architecture
title: Secret-injecting proxy
description: The local HTTP/HTTPS forward proxy behind `nokey proxy start` and `nokey exec --isolate`. It decrypts HTTPS for hosts named in proxy rules (MITM), injects secret-bearing headers, enforces credential, SNI and Host checks, can block egress, and signs with a name-constrained local CA whose private key is stored in the keyring.
tags: [proxy, mitm, tls, ca, egress, policy]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-19T03:41:24.016Z
sources:
  - id: openwiki-source-964e771d97b07ae87895d623
    resource: repo://cmd/exec.go
  - id: openwiki-source-3d0388561aa819a4641a4fdd
    resource: repo://cmd/proxy.go
  - id: openwiki-source-b42619e1af2329ab96530f17
    resource: repo://internal/policy/proxy.go
  - id: openwiki-source-903bb712408dddecd7e14f81
    resource: repo://internal/proxy/ca.go
  - id: openwiki-source-5a56f09598e4d6e663b8406e
    resource: repo://internal/proxy/rules.go
  - id: openwiki-source-a0eed2b8ecc68b0dd7997df7
    resource: repo://internal/proxy/server.go
generated: { by: "claude-code", at: "2026-11-19T03:41:24.016Z" }
---

# Secret-injecting proxy

The proxy lets a program call an API **without ever holding the secret**. The program sends its HTTPS requests through a local forward proxy. For hosts that a `proxy:` rule names, the proxy decrypts the request, adds headers built from keyring secrets, and forwards it.

The code lives in:

- `internal/proxy`: server, rules and CA;
- `internal/policy/proxy.go`: the rule schema;
- `cmd/proxy.go` and `setupIsolationProxy` in `cmd/exec.go`: the commands.

## Rules (in `policies.yaml`)

```yaml
proxy:
  rules:
    - hosts: ["api.openai.com"]
      headers:
        Authorization: "Bearer $OPENAI_API_KEY"
      ports: [443]        # optional; default 443 only
```

`ValidateProxyRules` checks each rule when the policy loads:

- A rule needs at least one host and one header.
- At least one header must reference a secret as `$NAME`. `$$` is a literal dollar sign.
- Ports must be between 1 and 65535.
- `approval: always` is rejected, both per rule and globally, because the proxy cannot prompt. Only `never` or an empty value is accepted.

The secret names referenced by a rule are computed into `rule.Secrets`. Host patterns use the same glob matching as command and secret patterns in the policy, and a malformed pattern matches nothing. `AllowsPort` accepts only 443 when a rule lists no ports, so a rule doesn't hand its secret to whatever else listens on the host. Rules come only from the **approved** policy (`loadApprovedPolicy`). See [Policy file](../security/policies.md).

## Starting it

**`nokey proxy start [--addr 127.0.0.1:0]`** runs these steps:

1. Validate that the listen address is loopback. This happens *before* the keyring is touched.
2. Load the approved policy. Fail if it has no proxy rules.
3. Load or create the CA.
4. Ask for human confirmation (`confirmHuman`), naming the secrets that will be injected for as long as the proxy runs.
5. Read those secrets once, start the proxy, and print the proxy URL.
6. Run until SIGINT or SIGTERM.

**`nokey exec --isolate`** starts the same server on `127.0.0.1:0` with `SetBlockUnmatched(true)` and points the child at it with environment variables:

- `http(s)_proxy` and `all_proxy`, in both lower and upper case;
- empty `no_proxy`/`NO_PROXY`, so an inherited bypass list can't skip the filter;
- `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE`, set to the CA certificate.

The proxy only works on clients that honour proxy environment variables.

**`proxy init-ca`** creates the CA. **`proxy trust-ca`** prints instructions for trusting it. `--system` adds the system trust-store commands, which are not recommended.

## Request handling (`internal/proxy/server.go`)

### Access control

The server listens only on loopback. `ValidateListenAddr` runs before binding, and the listener is checked again after.

Every proxy URL carries a fresh random credential (`rand.Text()`) as the Basic auth password. A request without it gets `407`, which is audited. The `Proxy-Authorization` header is removed before anything goes upstream. As a result, another local process can't use a running proxy to get secrets injected into its own requests.

### Plain HTTP

The proxy **never injects into plain HTTP**:

- A request to a host that has a rule gets `403`, because the secret would cross the network unencrypted.
- With egress blocking on, a request to any other host also gets `403`.
- Otherwise the request is forwarded without injection.

### CONNECT (HTTPS)

1. With egress blocking on, refuse with `403` if no rule matches the host and port.
2. If **no rule names the host**, tunnel the raw bytes without decrypting. The CA couldn't sign for that host anyway.
3. Otherwise, terminate TLS with a leaf certificate for the host (TLS 1.2 or later, HTTP/1.1 forced). For a DNS host, **require the TLS SNI to equal the CONNECT host**; missing SNI is refused too.
4. For each request inside the tunnel, **require the `Host` header to match the CONNECT host**; otherwise answer `421`. Then resolve the headers of every matching rule and set them. If a referenced secret is missing, answer `502` and do *not* send the request without its header.
5. Forward with a transport whose `Proxy` is nil. nokey's own `HTTP(S)_PROXY` is ignored, so injected headers go only to the host the rule names.

Every outcome is audited through the injected `AuditFunc` with an operation such as `proxy:https`, `proxy:https:blocked` or `proxy:unauthorized`, plus the host and secret names (see [Audit log](../security/audit-log.md)).

### Limits and shutdown

- Tunnel handshake timeout: 10s.
- Idle timeout: 120s.
- Leaf certificates are cached, up to 1024 entries, and renewed an hour before they expire.

`Stop` cancels upstream calls, closes the connections still open, and waits for them to finish before clearing the secrets held in memory.

## Local CA (`internal/proxy/ca.go`)

- The certificate is stored at `<config>/ca/ca-cert.pem`. The **private key is kept in the keyring** as the internal entry `__nokey_proxy_ca_key__`, through `caKeys` in `cmd/proxy.go`, not in a file. Any program running as the user can read a file.
- The CA carries **X.509 name constraints** limited to the rule hosts, so a stolen key can't sign for any other name. A CA for IP-only rules permits only the DNS name `nokey.invalid`, because a CA with no permitted DNS names could sign any.
- The CA is valid for 90 days and is replaced 7 days before it expires.
- It is also replaced when a rule host isn't covered, the key is lost, or a legacy file key `ca-key.pem` exists. The legacy key file is then deleted and stderr says to re-trust. Writes are key first, then certificate, written atomically under a directory lock so concurrent `--isolate` runs end up with one CA.
- Leaf certificates are ECDSA P-256, valid for 24h, never written to disk, and have SANs for exactly one host.

## Tests

- `internal/proxy/server_test.go` and `server_fuzz_test.go`: auth, SNI and Host mismatches, egress blocking, and the HTTP refusal.
- `ca_test.go`: name constraints, renewal and legacy-key migration.
- `rules_test.go` and `rules_fuzz_test.go`: template resolution.
- `internal/policy/proxy_test.go`: rule validation.
- `cmd/proxy_test.go`: the commands.

Related: [Policy file](../security/policies.md), [Threat model](../security/threat-model.md), [Command execution and output redaction](exec-and-redaction.md).
