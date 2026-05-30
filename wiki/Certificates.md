# Certificate Management

This document describes how LocalBridge manages TLS certificates for the MITM proxy, including CA generation, dynamic certificate creation, and the trust model.

---

## Trust Model

```
                    ┌──────────────┐
                    │  LocalBridge │
                    │  Root CA     │  ← Trusted by client devices
                    │  (ca.pem)    │
                    └──────┬───────┘
                           │ Signs
              ┌────────────┼────────────┐
              │            │            │
    ┌─────────▼──┐  ┌─────▼────┐  ┌───▼──────────┐
    │ example.com │  │ test.com │  │ othersite.com│
    │ cert.pem    │  │ cert.pem │  │ cert.pem     │
    └─────────────┘  └──────────┘  └──────────────┘
         ↑                ↑               ↑
    Generated on-demand, cached on disk
```

For MITM to work, the client device must trust the LocalBridge CA. Once the CA certificate is imported as a trusted root CA on the device, all certificates signed by LocalBridge will be accepted by the device's TLS stack.

---

## CA Certificate

### Generation

The CA is generated once using `localbridge --init-ca` or automatically on first server start. It creates:

- **RSA 2048-bit key pair**: Standard key size for TLS CA certificates
- **Self-signed X.509 certificate**: With CA:TRUE basic constraint
- **10-year validity**: Long-lived root certificate

### CA Certificate Extensions

| Extension | Value | Critical |
|-----------|-------|----------|
| Basic Constraints | CA=TRUE, pathLength=None | Yes |
| Key Usage | keyCertSign, crlSign | Yes |
| Subject Key Identifier | Auto-generated | No |
| Authority Key Identifier | Auto-generated | No |

### File Security

- **CA Certificate** (`ca.pem`): Readable by all (644) — this is the public certificate shared with devices
- **CA Private Key** (`ca-key.pem`): Readable only by owner (600) — must be kept secret

---

## Dynamic Certificate Generation

### Per-Domain Certificates

When the MITM proxy intercepts a connection to a non-pinned domain, it generates a certificate specifically for that domain:

1. **Generate RSA 2048-bit key pair** for the domain
2. **Build X.509 certificate** with:
   - Common Name = domain name
   - SAN = domain name + wildcard variant
   - Issuer = LocalBridge CA
3. **Sign with CA private key**
4. **Cache on disk** for future connections

### Certificate Extensions

| Extension | Value | Critical |
|-----------|-------|----------|
| Subject Alternative Name | domain + *.domain | No |
| Basic Constraints | CA=FALSE | Yes |
| Key Usage | digitalSignature, keyEncipherment | Yes |
| Extended Key Usage | serverAuth | No |
| Subject Key Identifier | Auto-generated | No |
| Authority Key Identifier | From CA public key | No |

### Caching Strategy

Certificates are cached both in memory and on disk:

- **Memory cache**: Dictionary lookup — instant access for active connections
- **Disk cache**: SHA-256 hash of domain as filename — persists across restarts
- **Cache invalidation**: Manual via `clear_cache()` or by deleting cache directory

---

## Importing the CA Certificate

### Android

1. Transfer `ca.pem` to the device (USB, email, cloud storage)
2. Go to **Settings → Security → Install certificate from storage**
3. Select `ca.pem`
4. Name it "LocalBridge CA"
5. Select trust scope: **VPN and apps**

> **Note**: On Android 7+, user-installed CAs are not trusted by apps by default. Apps must explicitly opt in, or the device must be rooted to install system-level CAs.

### Windows

1. Double-click `ca.pem`
2. Click **Install Certificate**
3. Select **Local Machine** (requires admin)
4. Select **Place all certificates in the following store**
5. Browse to **Trusted Root Certification Authorities**
6. Click **Finish**

### macOS

1. Double-click `ca.pem`
2. Add to **System** keychain
3. Open Keychain Access, find "LocalBridge CA"
4. Double-click → **Trust** → Set to **Always Trust**

### Linux

```bash
sudo cp ca.pem /usr/local/share/ca-certificates/localbridge-ca.crt
sudo update-ca-certificates
```

---

## Security Best Practices

1. **Protect the CA private key** — anyone with the key can generate trusted certificates
2. **Use on trusted networks only** — this proxy is designed for local/LAN use
3. **Regenerate CA periodically** — especially if the key may have been compromised
4. **Remove CA from devices** when no longer needed
5. **Never commit** `ca-key.pem` to version control (it's in `.gitignore`)
