# Security Considerations

This document covers the security model, risks, and best practices for using LocalBridge.

---

## Security Model

LocalBridge operates as a **local network proxy** designed for use in **trusted environments**. The security model assumes:

1. The proxy machine (your laptop) is under your physical control
2. The local network is trusted (home/office LAN)
3. The CA private key is protected from unauthorized access
4. Only devices you control connect to the proxy

---

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Pinned apps breaking from MITM | Selective tunneling bypasses MITM entirely |
| CA key compromise | File permissions (600), .gitignore exclusion |
| Unauthorized proxy access | Optional SOCKS5 authentication |
| Traffic logging privacy | Logging disabled by default for content |

### Out of Scope

| Threat | Reason |
|--------|--------|
| Man-in-the-middle on the network | Not a network security tool |
| Remote attackers on the internet | Designed for local network only |
| Malicious CA key usage | Requires physical access to proxy machine |
| Cross-device certificate trust | Each device must explicitly trust the CA |

---

## Key Security Measures

### 1. CA Private Key Protection

The CA private key is the most sensitive asset:

- **File permissions**: Set to `0600` (owner read/write only)
- **.gitignore**: Never committed to version control
- **No network exposure**: Key never leaves the proxy machine
- **Optional encryption**: Could be extended with password-protected key storage

### 2. Selective MITM Isolation

The most critical security feature: **pinned domains never touch the MITM code path**.

```
Pinned domain → TCPTunnel (separate module, no TLS code)
Non-pinned domain → MITMProxy (separate module, TLS interception)
```

This separation means there's no code path where a pinned domain could accidentally be intercepted.

### 3. No Content Logging

By default, LocalBridge does NOT log traffic content:
- Access logs record only domain, port, and classification decision
- Diagnostic logs record connection lifecycle events
- No traffic payload is ever written to disk

### 4. Connection Limits

Configurable maximum connection limit prevents resource exhaustion:
- Default: 1000 concurrent connections
- Excess connections are immediately rejected
- Active connection count is tracked for monitoring

---

## Risks and Mitigations

### Risk: CA Certificate Compromise

If an attacker obtains your CA private key, they can generate trusted certificates for any domain, enabling MITM attacks on any device that trusts your CA.

**Mitigations**:
- Keep the key file permissions restrictive (600)
- Never share the key file
- Store the key on an encrypted filesystem if available
- Regenerate the CA if you suspect compromise (requires re-importing on all devices)

### Risk: Unauthorized Proxy Access

On an untrusted network, anyone could connect to your SOCKS5 proxy.

**Mitigations**:
- Enable SOCKS5 authentication (`authentication.enabled = true`)
- Bind to a specific interface instead of `0.0.0.0`
- Use firewall rules to restrict access
- Only run the proxy when needed

### Risk: Pinned Domain Misclassification

If a pinned domain is incorrectly classified as non-pinned, the MITM proxy will attempt to intercept it, causing a certificate error in the app.

**Mitigations**:
- The default pinned list covers major services with certificate pinning
- Users can add custom pinned domains via the override file
- Misclassification is a usability issue, not a security vulnerability (the connection fails safely)

### Risk: DNS-Based Classification Bypass

For IP-based connections, classification depends on reverse DNS, which could be spoofed or unavailable.

**Mitigations**:
- IP range matching provides a fallback for known IP blocks
- If classification cannot be determined, the default is "non-pinned" (safe — just may cause app errors)
- Most modern SOCKS5 clients send domain names (ATYP=0x03) for HTTPS

---

## Best Practices

1. **Only use on trusted networks** — home LAN, personal hotspot, etc.
2. **Enable authentication** when others share the network
3. **Protect the CA private key** — treat it like a password
4. **Remove CA trust from devices** when no longer using the proxy
5. **Regularly review** the pinned domains list for accuracy
6. **Monitor access logs** for unexpected connections
7. **Keep the software updated** for security patches
8. **Use HTTPS** for the MITM proxy — it's TLS-aware by design

---

## Compliance Notes

- This tool is designed for **legitimate network debugging and testing**
- Intercepting HTTPS traffic without authorization may violate laws in some jurisdictions
- Always obtain proper authorization before intercepting traffic
- The selective MITM feature is specifically designed to **avoid** breaking security protections (certificate pinning) of sensitive applications
