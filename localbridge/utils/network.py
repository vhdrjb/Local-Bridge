"""
Network Utilities for LocalBridge.

Provides helper functions for DNS resolution, IP range checking,
SNI extraction from TLS ClientHello, and other network-level operations
needed by the classifier and proxy components.
"""

import ipaddress
import socket
import struct
from typing import Optional, Tuple


def resolve_domain(domain: str, timeout: float = 5.0) -> Optional[str]:
    """Resolve a domain name to its first IPv4 address.

    Uses the system DNS resolver with a configurable timeout.
    Returns None if resolution fails for any reason.

    Args:
        domain: The hostname to resolve.
        timeout: Maximum time in seconds to wait for resolution.

    Returns:
        The first IPv4 address as a string, or None on failure.
    """
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        if results:
            return results[0][4][0]
    except (socket.gaierror, socket.timeout, OSError):
        pass
    return None


def reverse_dns(ip_address: str, timeout: float = 5.0) -> Optional[str]:
    """Perform reverse DNS lookup on an IP address.

    Useful when clients connect by IP — we need the hostname
    to classify the connection as pinned or non-pinned.

    Args:
        ip_address: The IPv4 address to look up.
        timeout: Maximum time in seconds to wait.

    Returns:
        The resolved hostname, or None on failure.
    """
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.timeout, OSError):
        return None


def ip_in_range(ip_address: str, cidr_ranges: list) -> bool:
    """Check if an IP address falls within any of the given CIDR ranges.

    Used by the domain classifier to match connections by IP range,
    which is important for services like Telegram that use well-known IP blocks.

    Args:
        ip_address: The IPv4 address to check (e.g., "149.154.167.50").
        cidr_ranges: List of CIDR strings (e.g., ["149.154.167.0/24"]).

    Returns:
        True if the IP falls within any range, False otherwise.
    """
    try:
        target = ipaddress.ip_address(ip_address)
        for cidr in cidr_ranges:
            if target in ipaddress.ip_network(cidr, strict=False):
                return True
    except (ValueError, TypeError):
        pass
    return False


def parse_sni_from_clienthello(data: bytes) -> Optional[str]:
    """Extract the Server Name Indication (SNI) from a TLS ClientHello.

    When a client sends an IP address in the SOCKS5 request instead of a domain,
    we can peek at the TLS ClientHello to determine the intended hostname.
    This is critical for accurate domain classification.

    The parsing follows RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3)
    ClientHello structure to locate the SNI extension.

    Args:
        data: Raw bytes from the start of a TLS connection (at least 4096 recommended).

    Returns:
        The SNI hostname string, or None if not found or data is malformed.
    """
    try:
        # Minimum TLS record header: 5 bytes
        if len(data) < 5:
            return None

        # TLS record: ContentType(1) + Version(2) + Length(2)
        content_type = data[0]
        if content_type != 0x16:  # Handshake
            return None

        # Handshake: HandshakeType(1) + Length(3)
        offset = 5
        if len(data) < offset + 4:
            return None

        handshake_type = data[offset]
        if handshake_type != 0x01:  # ClientHello
            return None

        offset += 4  # Skip handshake header

        # ClientHello: Version(2) + Random(32) + SessionID(variable)
        offset += 2  # Skip client version
        offset += 32  # Skip random

        # Session ID length + session ID
        if len(data) < offset + 1:
            return None
        session_id_length = data[offset]
        offset += 1 + session_id_length

        # Cipher suites length + cipher suites
        if len(data) < offset + 2:
            return None
        cipher_suites_length = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2 + cipher_suites_length

        # Compression methods length + compression methods
        if len(data) < offset + 1:
            return None
        compression_methods_length = data[offset]
        offset += 1 + compression_methods_length

        # Extensions length
        if len(data) < offset + 2:
            return None
        extensions_length = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2

        # Iterate through extensions to find SNI (extension type 0x0000)
        extensions_end = offset + extensions_length
        while offset + 4 <= extensions_end:
            ext_type = struct.unpack("!H", data[offset : offset + 2])[0]
            ext_length = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4

            if ext_type == 0x0000:  # SNI extension
                # SNI list length(2) + SNI type(1) + SNI length(2) + SNI hostname
                if ext_length < 5:
                    return None
                sni_list_length = struct.unpack("!H", data[offset : offset + 2])[0]
                sni_type = data[offset + 2]
                if sni_type != 0x00:  # host_name
                    return None
                sni_length = struct.unpack("!H", data[offset + 3 : offset + 5])[0]
                hostname = data[offset + 5 : offset + 5 + sni_length].decode("ascii")
                return hostname

            offset += ext_length

    except (IndexError, struct.error, UnicodeDecodeError):
        pass

    return None


def get_local_ip() -> str:
    """Determine the local network IP address of this machine.

    Creates a UDP socket to a public address (no data is sent)
    to determine which local interface would be used for outbound traffic.
    Falls back to 127.0.0.1 if detection fails.

    Returns:
        The local IPv4 address as a string.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to a public DNS server — no packets are actually sent
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def format_address(host: str, port: int) -> str:
    """Format a host:port pair for logging.

    Args:
        host: The hostname or IP address.
        port: The TCP port number.

    Returns:
        A formatted string like "example.com:443".
    """
    return f"{host}:{port}"
