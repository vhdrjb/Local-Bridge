# Architecture Overview

This document describes the internal architecture of LocalBridge — how components interact, data flows through the system, and the design decisions behind each module.

---

## System Architecture

LocalBridge follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────┐
│                    CLI / Main                     │
│              (Argument parsing, startup)           │
├─────────────────────────────────────────────────┤
│                  SOCKS5 Server                    │
│        (Protocol handling, connection mgmt)       │
├─────────────────────────────────────────────────┤
│                  Proxy Router                     │
│      (Decision engine: tunnel vs. MITM)          │
├───────────────┬─────────────────────────────────┤
│   Domain      │          Certificate             │
│  Classifier   │         Management               │
├───────────────┼─────────────────────────────────┤
│  TCP Tunnel   │         MITM Proxy               │
│ (Pinned)      │       (Non-Pinned)               │
└───────────────┴─────────────────────────────────┘
```

---

## Component Responsibilities

### 1. CLI / Main (`localbridge/main.py`)
- Parses command-line arguments
- Loads and validates configuration
- Initializes all subsystems
- Manages the server lifecycle (start, graceful shutdown)
- Sets up signal handlers

### 2. SOCKS5 Server (`localbridge/socks5/`)
The entry point for all client connections. Handles the SOCKS5 protocol:
- **Handshake** (`handshake.py`): Method negotiation and request parsing
- **Authentication** (`auth.py`): Optional username/password verification
- **Server** (`server.py`): Async TCP listener with connection management

After a successful SOCKS5 handshake, the parsed request is passed to the Proxy Router.

### 3. Proxy Router (`localbridge/proxy/router.py`)
The central decision engine. For each connection:
1. Resolves the destination domain (using reverse DNS if needed for IP-based connections)
2. Queries the Domain Classifier to determine if the domain is pinned
3. Routes to either the TCP Tunnel or MITM Proxy

### 4. Domain Classifier (`localbridge/classifier/`)
Determines if a domain should be tunneled or intercepted:
- **Exact match**: `github.com` → pinned
- **Wildcard match**: `*.telegram.org` → pinned (matches subdomains)
- **IP range match**: `149.154.167.0/24` → pinned (Telegram IP blocks)

### 5. TCP Tunnel (`localbridge/proxy/tunnel.py`)
For pinned domains — transparent byte relay:
- Raw TCP connection to destination (NO TLS inspection)
- Bidirectional relay with zero modification
- Apps see legitimate server certificates

### 6. MITM Proxy (`localbridge/proxy/mitm.py`)
For non-pinned domains — TLS interception:
- Generates CA-signed certificate for the destination
- Upgrades client connection to TLS (acting as server)
- Connects to real destination with verified TLS
- Relays traffic between two TLS sessions

### 7. Certificate Management (`localbridge/certificate/`)
- **CA** (`ca.py`): One-time root CA generation and loading
- **Generator** (`generator.py`): Per-domain certificate generation with caching

---

## Data Flow

### Pinned Domain Connection (e.g., Telegram)

```
1. Client sends SOCKS5 CONNECT to telegram.org:443
2. SOCKS5 Server performs handshake → success
3. Router queries Classifier → "telegram.org is pinned"
4. Router delegates to TCP Tunnel
5. Tunnel connects to telegram.org:443 (raw TCP)
6. Tunnel sends SOCKS5 success reply to client
7. Client initiates TLS handshake → passes through untouched
8. Bidirectional byte relay until disconnect
```

### Non-Pinned Domain Connection (e.g., example.com)

```
1. Client sends SOCKS5 CONNECT to example.com:443
2. SOCKS5 Server performs handshake → success
3. Router queries Classifier → "example.com is not pinned"
4. Router delegates to MITM Proxy
5. MITM generates certificate for example.com
6. MITM connects to example.com:443 with verified TLS
7. MITM sends SOCKS5 success reply to client
8. Client initiates TLS → MITM acts as TLS server (with generated cert)
9. Two TLS sessions: client↔proxy and proxy↔server
10. Bidirectional relay with optional modification
```

---

## Design Decisions

### Why Asyncio?
Python's asyncio provides efficient concurrent I/O handling for thousands of simultaneous connections. The entire proxy is non-blocking, using `async/await` throughout.

### Why Separate Tunnel and MITM?
The separation enforces the critical rule: **pinned traffic must NEVER touch TLS**. By having completely separate code paths, there's no risk of accidentally applying MITM logic to pinned connections.

### Why Cached Certificates?
Generating RSA keys and signing certificates is computationally expensive. Caching avoids regenerating certificates for frequently accessed domains, improving performance significantly.

### Why YAML for Pinned Domains?
YAML provides a clean, human-readable format for the pinned domains list. The user override file uses a simpler text format (one domain per line) for ease of editing.

---

## Error Handling Strategy

- **Connection errors**: SOCKS5 error replies sent to client with appropriate codes
- **TLS errors**: Logged and connection closed gracefully
- **Timeout errors**: Connection timeout and idle timeout configurable
- **DNS failures**: Non-critical — classification falls back to "not pinned"
- **CA errors**: Fatal — server cannot start without valid CA
