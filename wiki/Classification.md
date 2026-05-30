# Domain Classification

This document describes how LocalBridge determines whether a domain should be tunneled (pinned) or intercepted (non-pinned).

---

## Classification Decision Tree

```
Incoming Connection (domain or IP)
         │
         ▼
   ┌─────────────┐
   │ Exact Match? │── Yes → PINNED (tunnel)
   └──────┬──────┘
          │ No
          ▼
   ┌───────────────┐
   │ Wildcard Match?│── Yes → PINNED (tunnel)
   └──────┬────────┘
          │ No
          ▼
   ┌───────────────┐
   │ IP Range Match?│── Yes → PINNED (tunnel)
   └──────┬────────┘
          │ No
          ▼
   NON-PINNED (MITM)
```

---

## Matching Strategies

### 1. Exact Match

The simplest check — is the domain name in the pinned list?

```
github.com → exact match → PINNED
example.com → no exact match → continue to wildcard check
```

Domain names are normalized to lowercase before comparison.

### 2. Wildcard Match

Wildcard patterns use the `*.domain` syntax to match all subdomains:

```
*.telegram.org matches:
  ✅ api.telegram.org
  ✅ web.telegram.org
  ✅ telegram.org (base domain also matches)

*.telegram.org does NOT match:
  ❌ telegram.org.evil.com
  ❌ fake-telegram.org
```

The matching logic strips the `*.` prefix and checks if the target domain either equals the base or ends with `.{base}`. This prevents subdomain takeover attacks.

### 3. IP Range Match

Some services (like Telegram) use well-known IP blocks. Even when a client connects by IP address instead of domain, we can detect these:

```
149.154.167.50 → in 149.154.167.0/24 → PINNED (Telegram)
91.108.4.100 → in 91.108.4.0/24 → PINNED (Telegram)
8.8.8.8 → not in any pinned range → NON-PINNED
```

IP range matching is performed after DNS resolution for domain-based connections.

---

## Configuration Sources

The pinned domains list is loaded from two sources, merged at startup:

### Default YAML Configuration

File: `config/pinned_domains.yaml`

```yaml
pinned_domains:
  - "*.telegram.org"
  - "github.com"
  - "149.154.167.0/24"
```

### User Override File

File: `~/.localbridge/pinned_domains.txt`

```
# One domain per line, supports wildcards
*.mybank.com
*.private-service.com
```

User overrides are additive — they extend the default list, never remove entries.

---

## IP-Based Connections

When a SOCKS5 client connects using an IP address (ATYP=0x01 or 0x04) instead of a domain name:

1. **First**: Check if the IP falls in any pinned IP range
2. **Then**: Attempt reverse DNS lookup to get the domain name
3. **If resolved**: Classify using the resolved domain name
4. **If not resolved**: Classify as non-pinned (safe default)

This ensures that connections to pinned services work correctly even when the client doesn't send a domain name.

---

## Adding Custom Pinned Domains

To add your own pinned domains:

1. Create the user override file:
   ```bash
   mkdir -p ~/.localbridge
   nano ~/.localbridge/pinned_domains.txt
   ```

2. Add one domain per line:
   ```
   *.mybank.com
   corporate-vpn.example.com
   10.0.0.0/8
   ```

3. Restart LocalBridge for changes to take effect

---

## Classification API

The `DomainClassifier` class provides two main methods:

### `is_pinned(domain, port=0) -> bool`

Simple boolean classification:
```python
classifier = DomainClassifier(config)
if classifier.is_pinned("api.telegram.org"):
    # Route to TCP tunnel
else:
    # Route to MITM proxy
```

### `get_classification_info(domain) -> dict`

Detailed classification info for debugging:
```python
info = classifier.get_classification_info("api.telegram.org")
# Returns:
# {
#     "domain": "api.telegram.org",
#     "pinned": True,
#     "match_type": "wildcard",
#     "matched_pattern": "*.telegram.org"
# }
```
