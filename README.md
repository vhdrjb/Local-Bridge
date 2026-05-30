# LocalBridge - Selective MITM Proxy with SOCKS5

A local proxy solution that runs on your laptop, accepts SOCKS5 connections from other devices, and intelligently handles certificate-pinned applications by **NOT** performing MITM on them while still allowing modification of non-pinned traffic.

**Key Innovation**: Selective MITM — tunnel pinned connections, intercept only non-pinned.

---

## How It Works

```
┌──────────────────────────────────────────────────────────────────┐
│                        YOUR LAPTOP                               │
│                                                                   │
│  ┌─────────────────┐    ┌──────────────────────────────────────┐ │
│  │  SOCKS5 Server  │───>│        Domain Classifier             │ │
│  │  (Port 1080)    │    │  ┌──────────┬────────────────────┐   │ │
│  └─────────────────┘    │  │ PINNED   │ NON-PINNED         │   │ │
│                         │  └────┬─────┴──────┬─────────────┘   │ │
│                         └───────┼────────────┼─────────────────┘ │
│                                 │            │                   │
│                          ┌──────▼──────┐ ┌───▼────────────┐     │
│                          │ TCP Tunnel  │ │  MITM Proxy    │     │
│                          │ (No MITM)   │ │  (Decrypt)     │     │
│                          └──────┬──────┘ └───┬────────────┘     │
│                                 │            │                   │
└─────────────────────────────────┼────────────┼───────────────────┘
                                  │            │
                                  ▼            ▼
                            ┌─────────────────────────┐
                            │       INTERNET          │
                            └─────────────────────────┘
```

**Pinned domains** (Telegram, YouTube, WhatsApp, etc.) are tunneled transparently — the proxy relays bytes without touching TLS, so apps see legitimate certificates.

**Non-pinned domains** are intercepted by the MITM proxy — the proxy presents a CA-signed certificate (which the client trusts after importing the CA cert) and can inspect/modify traffic.

---

## Features

- **Selective MITM**: Automatically detects pinned vs. non-pinned domains
- **SOCKS5 Protocol**: Standard SOCKS5 proxy — works with any SOCKS5 client
- **Certificate Pinning Safe**: Pinned apps (Telegram, YouTube, etc.) work without errors
- **Dynamic Certificate Generation**: Per-domain certificates signed by your own CA
- **Wildcard Domain Matching**: `*.telegram.org` matches all subdomains
- **IP Range Matching**: Telegram IP blocks detected even without domain names
- **User-Configurable Override**: Add your own pinned domains via text file
- **Cross-Platform**: Works on Windows, macOS, and Linux (Python 3.9+)
- **No VPS Required**: Runs entirely on your local machine
- **Optional Authentication**: SOCKS5 username/password support

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/vhdrjb/Local-Bridge.git
cd Local-Bridge
pip install -e .
```

### 2. Generate CA Certificate

```bash
localbridge --init-ca
```

This creates `certs/ca.pem` and `certs/ca-key.pem`.

### 3. Import CA on Client Devices

Transfer `certs/ca.pem` to each device and install it as a trusted CA:

| Platform | Instructions |
|----------|-------------|
| **Android** | Settings → Security → Install certificate from storage → Select "VPN and apps" |
| **Windows** | Double-click `ca.pem` → Install Certificate → Local Machine → Trusted Root CA |
| **macOS** | Double-click `ca.pem` → Add to Keychain → Set to "Always Trust" |
| **Linux** | `sudo cp ca.pem /usr/local/share/ca-certificates/ && sudo update-ca-certificates` |

### 4. Start the Proxy

```bash
localbridge
```

### 5. Configure Client Devices

Set the SOCKS5 proxy on your devices:

| Setting | Value |
|---------|-------|
| Server | Your laptop's local IP (e.g., `192.168.1.100`) |
| Port | `1080` |
| Type | SOCKS5 |

**Android**: Use apps like SocksDroid, ProxyDroid, or Postern for per-app SOCKS5.

**Desktop**: Set `ALL_PROXY=socks5://192.168.1.100:1080` or use `proxychains`.

---

## Configuration

### Command Line Options

```
localbridge [--config FILE] [--port PORT] [--host HOST] [--log-level LEVEL] [--init-ca]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--config, -c` | Configuration file path | `config/localbridge.conf` |
| `--port, -p` | SOCKS5 listening port | `1080` |
| `--host` | Bind address | `0.0.0.0` |
| `--log-level` | Log level (DEBUG/INFO/WARNING/ERROR) | `INFO` |
| `--init-ca` | Generate CA and exit | — |

### Configuration File

See [`config/localbridge.conf`](config/localbridge.conf) for all options:

```ini
[server]
host = 0.0.0.0
port = 1080
max_connections = 1000

[authentication]
enabled = false
username =
password =

[certificate]
ca_path = ./certs/ca.pem
ca_key_path = ./certs/ca-key.pem
cert_cache_dir = ./certs/cache
cert_validity_days = 365

[pinned_domains]
config_file = ./config/pinned_domains.yaml
user_override_file = ~/.localbridge/pinned_domains.txt

[logging]
level = INFO
log_file = ./logs/localbridge.log
access_log = ./logs/access.log

[performance]
buffer_size = 8192
connection_timeout = 30
idle_timeout = 300
```

---

## Pinned Domains

Domains listed in the pinned domains configuration are **never** intercepted. Traffic to these domains is tunneled transparently so certificate-pinned applications work correctly.

### Default Pinned Domains

See [`config/pinned_domains.yaml`](config/pinned_domains.yaml) for the full list, which includes:

- **Telegram**: `*.telegram.org`, `*.t.me`, Telegram IP ranges
- **YouTube/Google**: `*.youtube.com`, `*.googlevideo.com`, `*.gstatic.com`
- **WhatsApp**: `*.whatsapp.net`, `*.whatsapp.com`
- **Signal**: `*.signal.org`, `*.whispersystems.org`
- **Google Auth**: `accounts.google.com`, `play.googleapis.com`
- **Apple**: `*.apple.com`, `*.icloud.com`
- **Microsoft**: `*.live.com`, `login.microsoftonline.com`
- **Social Media**: `*.facebook.com`, `*.instagram.com`
- **GitHub**: `github.com`, `api.github.com`

### Adding Custom Pinned Domains

Create `~/.localbridge/pinned_domains.txt`:

```
# One domain per line, supports wildcards
*.mybank.com
*.private-service.com
```

---

## Architecture

For detailed architecture documentation, see:
- [Architecture Overview](wiki/Architecture.md) — System design and component interactions
- [SOCKS5 Implementation](wiki/SOCKS5.md) — Protocol implementation details
- [Certificate Management](wiki/Certificates.md) — CA and dynamic cert generation
- [Domain Classification](wiki/Classification.md) — How pinned domains are detected
- [Security Considerations](wiki/Security.md) — Security model and best practices
- [Client Setup Guide](wiki/ClientSetup.md) — Device-specific configuration instructions

---

## Project Structure

```
localbridge/
├── localbridge/
│   ├── main.py                 # Entry point and CLI
│   ├── config.py               # Configuration management
│   ├── socks5/
│   │   ├── server.py           # SOCKS5 async TCP server
│   │   ├── auth.py             # Authentication handler
│   │   └── handshake.py        # SOCKS5 protocol handshake
│   ├── proxy/
│   │   ├── tunnel.py           # TCP tunnel (pinned domains)
│   │   ├── mitm.py             # MITM proxy (non-pinned domains)
│   │   └── router.py           # Connection routing engine
│   ├── classifier/
│   │   ├── domain.py           # Domain classification engine
│   │   └── pinned_list.py      # Pinned domains database
│   ├── certificate/
│   │   ├── ca.py               # Certificate Authority management
│   │   └── generator.py        # Dynamic cert generation
│   └── utils/
│       ├── logger.py           # Structured logging setup
│       └── network.py          # DNS, SNI, IP utilities
├── config/
│   ├── localbridge.conf        # Main config file
│   ├── pinned_domains.yaml     # Default pinned domains
│   └── pinned_domains.txt      # User override template
├── tests/
│   ├── test_classifier.py      # Domain classifier tests
│   └── test_integration.py     # Integration tests
├── wiki/                       # Documentation wiki
└── requirements.txt
```

---

## Requirements

- Python 3.9+
- `cryptography` >= 41.0.0
- `pyyaml` >= 6.0
- `loguru` >= 0.7.0

Optional:
- `uvloop` >= 0.17.0 (Linux/macOS — improved async performance)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'feat: add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Create a Pull Request
