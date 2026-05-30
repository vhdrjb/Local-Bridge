# SOCKS5 Implementation

This document describes the SOCKS5 protocol implementation in LocalBridge, including supported features, protocol flow, and implementation details.

---

## Protocol Compliance

LocalBridge implements SOCKS5 as defined in:
- **RFC 1928**: SOCKS Protocol Version 5
- **RFC 1929**: Username/Password Authentication for SOCKS V5

---

## Supported Features

| Feature | Status |
|---------|--------|
| CONNECT command | ✅ Supported |
| BIND command | ❌ Not supported |
| UDP ASSOCIATE | ❌ Not supported |
| No Authentication (0x00) | ✅ Supported |
| Username/Password (0x02) | ✅ Supported |
| GSSAPI (0x01) | ❌ Not supported |
| IPv4 addresses | ✅ Supported |
| Domain names | ✅ Supported |
| IPv6 addresses | ✅ Supported |

---

## Connection Flow

### Phase 1: Method Negotiation

```
Client → Server:  [0x05, NMETHODS, METHOD_1, METHOD_2, ...]
Server → Client:  [0x05, SELECTED_METHOD]
```

The server selects the most secure method that both sides support. If authentication is enabled and the client supports it, Username/Password (0x02) is preferred.

### Phase 2: Authentication (if selected)

```
Client → Server:  [0x01, ULEN, USERNAME, PLEN, PASSWORD]
Server → Client:  [0x01, STATUS]  (0x00 = success, 0x01 = failure)
```

### Phase 3: Connection Request

```
Client → Server:  [0x05, CMD, 0x00, ATYP, DST.ADDR, DST.PORT]
Server → Client:  [0x05, REP, 0x00, ATYP, BND.ADDR, BND.PORT]
```

Where:
- `CMD` = 0x01 (CONNECT)
- `ATYP` = 0x01 (IPv4), 0x03 (Domain), 0x04 (IPv6)
- `REP` = Reply code (0x00 = success, others = error)

### Phase 4: Data Relay

After a successful CONNECT reply, data flows bidirectionally. For HTTPS connections, the client initiates TLS after the SOCKS5 reply.

---

## Implementation Details

### Address Type Handling

When the client sends a domain name (ATYP=0x03), the domain is used directly for classification and connection. When the client sends an IP address (ATYP=0x01 or 0x04), the router attempts reverse DNS lookup to determine the domain for classification purposes.

### Critical Timing: SOCKS5 + TLS

For HTTPS connections, the SOCKS5 reply MUST be sent before the TLS handshake begins. The client expects:

1. SOCKS5 handshake (plaintext) → success
2. SOCKS5 CONNECT reply (plaintext) → success
3. Client initiates TLS ClientHello

This means we must decide (tunnel vs. MITM) before the TLS handshake starts.

### Error Reply Codes

LocalBridge maps network errors to appropriate SOCKS5 reply codes:

| Error | SOCKS5 Reply Code |
|-------|-------------------|
| Connection refused | 0x05 (Connection refused) |
| Timeout | 0x06 (TTL expired) |
| DNS failure | 0x04 (Host unreachable) |
| Network error | 0x03 (Network unreachable) |
| General error | 0x01 (General failure) |

### Connection Limits

The server enforces a maximum connection limit (configurable, default 1000). When the limit is reached, new connections are immediately closed without SOCKS5 negotiation.
