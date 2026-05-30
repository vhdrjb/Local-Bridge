"""
SOCKS5 Authentication Handler.

Implements the authentication negotiation phase of the SOCKS5 protocol.
Supports No Authentication (0x00) and Username/Password (0x02) methods,
as defined in RFC 1928 and RFC 1929.
"""

from loguru import logger


# SOCKS5 authentication method constants (RFC 1928)
METHOD_NO_AUTH = 0x00
METHOD_USERNAME_PASSWORD = 0x02
METHOD_NO_ACCEPTABLE = 0xFF


class AuthHandler:
    """Handles SOCKS5 client authentication.

    Determines which authentication methods are acceptable based on
    configuration, and validates credentials when username/password
    authentication is required.

    Attributes:
        enabled: Whether username/password authentication is required.
        username: Expected username for authentication.
        password: Expected password for authentication.
    """

    def __init__(self, enabled: bool = False, username: str = "", password: str = ""):
        """Initialize the authentication handler.

        Args:
            enabled: If True, require username/password authentication.
            username: The valid username (only used when enabled=True).
            password: The valid password (only used when enabled=True).
        """
        self.enabled = enabled
        self.username = username
        self.password = password

    @property
    def supported_methods(self) -> list:
        """Return the list of supported SOCKS5 authentication methods.

        When authentication is enabled, both No-Auth and Username/Password
        are offered (the client will choose). When disabled, only No-Auth
        is offered.

        Returns:
            A list of method byte values supported by this handler.
        """
        methods = [METHOD_NO_AUTH]
        if self.enabled:
            methods.append(METHOD_USERNAME_PASSWORD)
        return methods

    def select_method(self, client_methods: list) -> int:
        """Select the best authentication method from client's offered methods.

        Prefers the most secure method that both sides support.
        If no common method exists, returns METHOD_NO_ACCEPTABLE.

        Args:
            client_methods: List of method byte values offered by the client.

        Returns:
            The selected method byte, or METHOD_NO_ACCEPTABLE if no match.
        """
        # Prefer username/password if we require auth
        if self.enabled and METHOD_USERNAME_PASSWORD in client_methods:
            return METHOD_USERNAME_PASSWORD

        # Fall back to no auth if client supports it
        if METHOD_NO_AUTH in client_methods:
            return METHOD_NO_AUTH

        # No acceptable method found
        return METHOD_NO_ACCEPTABLE

    async def authenticate(self, reader, writer) -> bool:
        """Perform username/password authentication (RFC 1929).

        Reads the credentials from the client stream and validates them
        against the configured username and password. Sends a response
        indicating success or failure.

        Args:
            reader: asyncio StreamReader for the client connection.
            writer: asyncio StreamWriter for the client connection.

        Returns:
            True if authentication succeeded, False otherwise.
        """
        # RFC 1929 format:
        # +----+------+----------+------+----------+
        # |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        # +----+------+----------+------+----------+
        # | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        # +----+------+----------+------+----------+
        try:
            data = await reader.readexactly(2)
            version = data[0]
            ulen = data[1]

            if version != 0x01:
                logger.warning("Unsupported auth sub-negotiation version: {}", version)
                writer.write(bytes([0x01, 0x01]))  # Failure
                await writer.drain()
                return False

            username_data = await reader.readexactly(ulen)
            username = username_data.decode("utf-8", errors="replace")

            plen_data = await reader.readexactly(1)
            plen = plen_data[0]

            password_data = await reader.readexactly(plen)
            password = password_data.decode("utf-8", errors="replace")

            # Validate credentials
            if username == self.username and password == self.password:
                writer.write(bytes([0x01, 0x00]))  # Success
                await writer.drain()
                logger.info("Authentication successful for user: {}", username)
                return True
            else:
                writer.write(bytes([0x01, 0x01]))  # Failure
                await writer.drain()
                logger.warning("Authentication failed for user: {}", username)
                return False

        except (asyncio.IncompleteReadError, ConnectionError) as e:
            logger.error("Authentication read error: {}", e)
            return False


# Import asyncio at module level for authenticate method
import asyncio
