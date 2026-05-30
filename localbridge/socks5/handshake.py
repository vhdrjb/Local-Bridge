"""
SOCKS5 Protocol Handshake Implementation.

Implements the initial handshake phase and request parsing of the
SOCKS5 protocol as defined in RFC 1928. This module handles:

1. Method negotiation — client and server agree on authentication
2. Request parsing — extract destination address and port from CONNECT requests
3. Reply construction — build success/failure responses

The handshake is the first step before any proxying occurs.
After a successful handshake, the connection is handed off to
the proxy router for tunneling or MITM processing.
"""

import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Tuple

from loguru import logger

from .auth import AuthHandler, METHOD_NO_AUTH, METHOD_NO_ACCEPTABLE


# ---------------------------------------------------------------------------
# SOCKS5 Protocol Constants (RFC 1928)
# ---------------------------------------------------------------------------

SOCKS_VERSION = 0x05

# Address types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Commands
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# Reserved byte
RSV = 0x00


class ReplyCode(IntEnum):
    """SOCKS5 reply codes as defined in RFC 1928 Section 6."""

    SUCCEEDED = 0x00
    GENERAL_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


@dataclass
class Socks5Request:
    """Parsed SOCKS5 connection request.

    Contains all information needed to route the connection:
    the desired command, the destination address (as domain or IP),
    and the destination port.

    Attributes:
        version: SOCKS protocol version (should be 0x05).
        command: Requested command (CONNECT, BIND, UDP ASSOCIATE).
        rsv: Reserved byte (should be 0x00).
        atyp: Address type (IPv4, domain, or IPv6).
        dest_host: Destination hostname or IP address string.
        dest_port: Destination port number.
    """

    version: int
    command: int
    rsv: int
    atyp: int
    dest_host: str
    dest_port: int


class Socks5Handshake:
    """Manages the SOCKS5 protocol handshake and request parsing.

    This class orchestrates the two-phase SOCKS5 initialization:
    1. Method negotiation — agree on authentication with the client
    2. Request processing — parse the CONNECT request and validate it

    After a successful handshake, the parsed Socks5Request is returned
    for the proxy router to handle.

    Attributes:
        auth_handler: The authentication handler for method selection.
    """

    def __init__(self, auth_handler: AuthHandler):
        """Initialize with an authentication handler.

        Args:
            auth_handler: Configured AuthHandler instance for credential validation.
        """
        self.auth_handler = auth_handler

    async def negotiate_method(self, reader, writer) -> bool:
        """Perform SOCKS5 method negotiation (RFC 1928 Section 3).

        Reads the client's greeting, selects the best authentication method,
        and sends the selection back. If username/password is selected,
        performs the sub-negotiation as defined in RFC 1929.

        Args:
            reader: asyncio StreamReader connected to the client.
            writer: asyncio StreamWriter connected to the client.

        Returns:
            True if method negotiation succeeded, False otherwise.
        """
        try:
            # Client greeting: VER | NMETHODS | METHODS
            header = await reader.readexactly(2)
            version = header[0]
            nmethods = header[1]

            if version != SOCKS_VERSION:
                logger.warning("Unsupported SOCKS version: {}", version)
                writer.close()
                return False

            methods_data = await reader.readexactly(nmethods)
            client_methods = list(methods_data)

            # Select the best method
            selected = self.auth_handler.select_method(client_methods)

            # Send method selection: VER | METHOD
            writer.write(bytes([SOCKS_VERSION, selected]))
            await writer.drain()

            if selected == METHOD_NO_ACCEPTABLE:
                logger.warning("No acceptable authentication method")
                writer.close()
                return False

            # If username/password is selected, perform sub-negotiation
            if selected == 0x02:
                auth_result = await self.auth_handler.authenticate(reader, writer)
                if not auth_result:
                    writer.close()
                    return False

            logger.debug("SOCKS5 method negotiation succeeded (method={})", selected)
            return True

        except Exception as e:
            logger.error("Method negotiation error: {}", e)
            return False

    async def parse_request(self, reader) -> Optional[Socks5Request]:
        """Parse the SOCKS5 connection request (RFC 1928 Section 4).

        Reads and decodes the client's CONNECT request, extracting the
        destination address and port. Supports IPv4, IPv6, and domain
        address types.

        Args:
            reader: asyncio StreamReader connected to the client.

        Returns:
            A Socks5Request instance if parsing succeeded, None otherwise.
        """
        try:
            # Request header: VER | CMD | RSV | ATYP
            header = await reader.readexactly(4)
            version = header[0]
            command = header[1]
            rsv = header[2]
            atyp = header[3]

            if version != SOCKS_VERSION:
                logger.warning("Invalid SOCKS version in request: {}", version)
                return None

            if command != CMD_CONNECT:
                logger.warning("Unsupported SOCKS command: {} (only CONNECT supported)", command)
                return None

            # Parse destination address based on address type
            dest_host = await self._parse_address(reader, atyp)
            if dest_host is None:
                return None

            # Parse destination port (2 bytes, network byte order)
            port_data = await reader.readexactly(2)
            dest_port = struct.unpack("!H", port_data)[0]

            request = Socks5Request(
                version=version,
                command=command,
                rsv=rsv,
                atyp=atyp,
                dest_host=dest_host,
                dest_port=dest_port,
            )

            logger.debug(
                "SOCKS5 request: CONNECT {}:{} (atyp={})",
                dest_host,
                dest_port,
                atyp,
            )
            return request

        except Exception as e:
            logger.error("Request parsing error: {}", e)
            return None

    async def _parse_address(self, reader, atyp: int) -> Optional[str]:
        """Parse the destination address from the client request.

        Handles all three SOCKS5 address types:
        - IPv4: 4 raw bytes
        - Domain: length-prefixed string
        - IPv6: 16 raw bytes

        Args:
            reader: asyncio StreamReader connected to the client.
            atyp: The address type byte from the SOCKS5 request.

        Returns:
            The destination address as a string, or None on error.
        """
        try:
            if atyp == ATYP_IPV4:
                addr_data = await reader.readexactly(4)
                return socket.inet_ntoa(addr_data)

            elif atyp == ATYP_DOMAIN:
                length_data = await reader.readexactly(1)
                length = length_data[0]
                domain_data = await reader.readexactly(length)
                return domain_data.decode("ascii")

            elif atyp == ATYP_IPV6:
                addr_data = await reader.readexactly(16)
                return socket.inet_ntop(socket.AF_INET6, addr_data)

            else:
                logger.warning("Unsupported address type: {}", atyp)
                return None

        except Exception as e:
            logger.error("Address parsing error: {}", e)
            return None

    @staticmethod
    def build_reply(
        reply_code: ReplyCode,
        bind_address: str = "0.0.0.0",
        bind_port: int = 0,
        atyp: int = ATYP_IPV4,
    ) -> bytes:
        """Construct a SOCKS5 reply message (RFC 1928 Section 6).

        Builds the binary reply sent to the client after processing
        their CONNECT request. On success, includes the bound address
        and port. On failure, includes the error code.

        Args:
            reply_code: The reply code indicating success or failure reason.
            bind_address: The server-side bound address (usually 0.0.0.0).
            bind_port: The server-side bound port (usually 0).
            atyp: Address type for the bind address.

        Returns:
            The complete SOCKS5 reply as bytes ready to send.
        """
        reply = struct.pack(
            "!BBBB", SOCKS_VERSION, reply_code, RSV, atyp
        )

        if atyp == ATYP_IPV4:
            reply += socket.inet_aton(bind_address)
        elif atyp == ATYP_DOMAIN:
            encoded = bind_address.encode("ascii")
            reply += struct.pack("!B", len(encoded)) + encoded
        elif atyp == ATYP_IPV6:
            reply += socket.inet_pton(socket.AF_INET6, bind_address)

        reply += struct.pack("!H", bind_port)
        return reply
