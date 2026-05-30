# Client Setup Guide

This guide covers how to configure various devices and applications to use LocalBridge as a SOCKS5 proxy.

---

## Prerequisites

Before configuring clients, ensure:
1. LocalBridge is running on your laptop
2. You know your laptop's local IP address (displayed at startup)
3. The CA certificate (`ca.pem`) has been installed on the client device

---

## Android

### Install CA Certificate

1. Transfer `ca.pem` to your Android device (USB, email, Google Drive, etc.)
2. Open **Settings → Security → Install certificate from storage**
3. Navigate to and select `ca.pem`
4. Name it "LocalBridge CA"
5. Select trust scope: **VPN and apps**
6. Confirm installation

> **Important**: On Android 7+, apps that target API 24+ do NOT trust user-installed CAs by default. This means pinned apps like Telegram won't use the CA, which is exactly what we want. For non-pinned apps that you want to intercept, they need to explicitly trust user CAs or the device must be rooted.

### Configure SOCKS5 Proxy

#### Option A: Per-App Proxy (Recommended)

Use one of these apps:
- **SocksDroid** (free, open source)
- **ProxyDroid** (requires root for per-app)
- **Postern** (feature-rich, paid)

Configure:
- **Proxy type**: SOCKS5
- **Server**: Your laptop's IP (e.g., `192.168.1.100`)
- **Port**: `1080`
- **Authentication**: None (or configure if enabled)

#### Option B: System-Wide Proxy (Requires Root)

1. Root the device
2. Use an app like ProxyDroid for system-wide SOCKS5
3. Configure the same server/port settings

#### Option C: Wi-Fi Proxy

Some Android versions support proxy settings per Wi-Fi network:
1. Long-press the connected Wi-Fi network
2. **Modify network → Advanced options → Proxy**
3. Set to **Manual**
4. Hostname: Your laptop's IP
5. Port: `1080`

> **Note**: Wi-Fi proxy only supports HTTP proxies, not SOCKS5. Use a per-app proxy app for SOCKS5 support.

---

## Windows

### Install CA Certificate

1. Double-click `ca.pem`
2. Click **Install Certificate**
3. Select **Local Machine** (requires administrator)
4. Select **Place all certificates in the following store**
5. Click **Browse → Trusted Root Certification Authorities**
6. Click **Next → Finish**
7. Accept the security warning

### Configure SOCKS5 Proxy

#### Environment Variable (Quick)

```cmd
set ALL_PROXY=socks5://192.168.1.100:1080
set HTTP_PROXY=socks5://192.168.1.100:1080
set HTTPS_PROXY=socks5://192.168.1.100:1080
```

Or PowerShell:
```powershell
$env:ALL_PROXY = "socks5://192.168.1.100:1080"
```

#### Proxychains (Recommended)

1. Install proxychains: `choco install proxychains` or download from GitHub
2. Edit `proxychains.conf`:
   ```
   [ProxyList]
   socks5 192.168.1.100 1080
   ```
3. Run applications:
   ```cmd
   proxychains firefox
   proxychains curl https://example.com
   ```

#### System Settings

Windows 10/11 supports manual proxy configuration:
1. **Settings → Network & Internet → Proxy**
2. Under **Manual proxy setup**, click **Set up**
3. Note: Windows system proxy supports HTTP/HTTPS, not SOCKS5 directly
4. Use a local HTTP-to-SOCKS5 converter like `privoxy` for system-wide SOCKS5

---

## macOS

### Install CA Certificate

1. Double-click `ca.pem`
2. Add to **System** keychain (requires admin password)
3. Open **Keychain Access** app
4. Find "LocalBridge CA" in the System keychain
5. Double-click the certificate
6. Expand **Trust** section
7. Set **When using this certificate** to **Always Trust**
8. Close and confirm with admin password

### Configure SOCKS5 Proxy

#### Environment Variable

```bash
export ALL_PROXY=socks5://192.168.1.100:1080
```

Add to `~/.zshrc` or `~/.bash_profile` for persistence.

#### System Preferences

1. **System Preferences → Network**
2. Select your active connection → **Advanced**
3. **Proxies** tab
4. Enable **SOCKS Proxy**
5. Server: Your laptop's IP, Port: `1080`
6. Click **OK → Apply**

#### Proxychains

```bash
brew install proxychains-ng
# Edit /usr/local/etc/proxychains.conf
# Add: socks5 192.168.1.100 1080
proxychains4 curl https://example.com
```

---

## Linux

### Install CA Certificate

```bash
sudo cp ca.pem /usr/local/share/ca-certificates/localbridge-ca.crt
sudo update-ca-certificates
```

For Firefox (uses its own certificate store):
1. Open **Settings → Privacy & Security**
2. **Certificates → View Certificates**
3. **Import** → Select `ca.pem`
4. Check "Trust this CA to identify websites"

### Configure SOCKS5 Proxy

#### Environment Variable

```bash
export ALL_PROXY=socks5://192.168.1.100:1080
```

#### Proxychains

```bash
sudo apt install proxychains4  # Debian/Ubuntu
# or
sudo dnf install proxychains-ng  # Fedora

# Edit /etc/proxychains4.conf
# Add: socks5 192.168.1.100 1080

proxychains4 telegram-desktop
proxychains4 firefox
```

#### GNOME System Proxy

1. **Settings → Network → Network Proxy**
2. Set to **Manual**
3. SOCKS Host: Your laptop's IP, Port: `1080`

---

## Verifying the Setup

### Test Non-Pinned (MITM) Connection

```bash
# Via proxy
curl --socks5 192.168.1.100:1080 https://httpbin.org/ip

# Should work — traffic intercepted by MITM proxy
```

### Test Pinned (Tunnel) Connection

```bash
# Telegram API via proxy
curl --socks5 192.168.1.100:1080 https://api.telegram.org/

# Should work — traffic tunneled without MITM
```

### Check CA Trust

```bash
# If CA is properly trusted, this should work without certificate errors
curl --socks5 192.168.1.100:1080 https://example.com
```

If you see certificate errors, the CA certificate is not properly trusted on the client device.

---

## Troubleshooting

| Problem | Likely Cause | Solution |
|---------|-------------|---------|
| App shows "certificate error" | CA not imported on device | Install ca.pem as trusted root CA |
| Pinned app fails to connect | Domain not in pinned list | Add domain to ~/.localbridge/pinned_domains.txt |
| Connection refused | Firewall blocking port 1080 | Open port 1080 on laptop firewall |
| Connection timeout | Wrong IP or proxy not running | Check IP and verify server is running |
| No internet through proxy | DNS resolution failing | Check network connectivity from laptop |
