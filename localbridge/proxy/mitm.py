"""
MITM Proxy for Non-Pinned Domains.

Intercepts and relays TLS traffic for domains that do not use certificate
pinning. The proxy performs a "man-in-the-middle" by presenting a
CA-signed certificate to the client while establishing a verified TLS
connection to the real server.

This enables:
- Traffic inspection and logging (when enabled)
- Content modification (for authorized use cases)
- Response header manipulation
- Request/response filtering

CRITICAL TIMING NOTE (RFC 1928):
For HTTPS connections via SOCKS5, the protocol flow is:
1. SOCKS5 handshake (plaintext)
2. SOCKS5 CONNECT reply (plaintext)
3. Client initiates TLS handshake
4. WE become the TLS server (using generated cert)
5. We establish real TLS connection to destination
6. Relay/modify traffic between the two TLS sessions
"""

import asyncio
import ssl
from typing import Optional

from loguru import logger

from ..config import Config
from ..socks5.handshake import Socks5Handshake, ReplyCode, ATYP_IPV4
from ..certificate.generator import CertificateGenerator
from ..utils.logger import get_access_logger


class MITMProxy:
    """Man-in-the-middle proxy for non-pinned HTTPS connections.

    For each connection, the proxy:
    1. Generates a CA-signed certificate for the destination domain
    2. Sends SOCKS5 success reply to the client
    3. Upgrades the client connection to TLS (using generated cert)
    4. Establishes a verified TLS connection to the real server
    5. Relays traffic between client and server (with optional modification)

    Attributes:
        cert_generator: Certificate generator for creating per-domain certs.
        config: Application configuration for buffer sizes and timeouts.
    """

    def __init__(self, cert_generator: CertificateGenerator, config: Config):
        """Initialize the MITM proxy.

        Args:
            cert_generator: CertificateGenerator instance for creating
                dynamically signed certificates.
            config: Application configuration.
        """
        self.cert_generator = cert_generator
        self.buffer_size = config.performance.buffer_size
        self.connection_timeout = config.performance.connection_timeout

    async def relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        dest_host: str,
        dest_port: int,
    ) -> None:
        """Intercept and relay a TLS connection to a non-pinned domain.

        This is the main entry point for MITM'd connections. The flow:
        1. Generate certificate for the destination domain
        2. Connect to the real destination with verified TLS
        3. Send SOCKS5 success reply to client
        4. Upgrade client connection to TLS (using generated cert)
        5. Bidirectional relay between two TLS sessions

        Args:
            client_reader: StreamReader for the SOCKS5 client.
            client_writer: StreamWriter for the SOCKS5 client.
            dest_host: Destination hostname.
            dest_port: Destination TCP port.
        """
        try:
            # Step 1: Generate certificate for this domain
            cert_path, key_path = self.cert_generator.generate_cert(dest_host)

            # Step 2: Connect to the real destination with verified TLS
            dest_tls_reader, dest_tls_writer = await asyncio.wait_for(
                self._connect_to_destination(dest_host, dest_port),
                timeout=self.connection_timeout,
            )

            # Step 3: Send SOCKS5 success reply (before TLS upgrade)
            reply = Socks5Handshake.build_reply(
                ReplyCode.SUCCEEDED,
                bind_address="0.0.0.0",
                bind_port=0,
                atyp=ATYP_IPV4,
            )
            client_writer.write(reply)
            await client_writer.drain()

            # Step 4: Upgrade client connection to TLS
            # The client will now send its TLS ClientHello
            client_tls_reader, client_tls_writer = await asyncio.wait_for(
                self._upgrade_client_tls(
                    client_reader, client_writer, dest_host, cert_path, key_path
                ),
                timeout=self.connection_timeout,
            )

            logger.info("MITM intercept established for {}:{}", dest_host, dest_port)

            # Log to access log
            access_logger = get_access_logger()
            access_logger.info("MITM {}:{} (intercepted)", dest_host, dest_port)

            # Step 5: Bidirectional relay between two TLS sessions
            await asyncio.gather(
                self._relay_stream(
                    client_tls_reader, dest_tls_writer, "client->dest"
                ),
                self._relay_stream(
                    dest_tls_reader, client_tls_writer, "dest->client"
                ),
                return_exceptions=True,
            )

        except asyncio.TimeoutError:
            logger.warning("MITM connection timeout to {}:{}", dest_host, dest_port)
            self._send_failure_reply(client_writer, ReplyCode.TTL_EXPIRED)

        except ConnectionRefusedError:
            logger.warning("MITM connection refused by {}:{}", dest_host, dest_port)
            self._send_failure_reply(client_writer, ReplyCode.CONNECTION_REFUSED)

        except ssl.SSLError as e:
            logger.error("MITM TLS error for {}:{}: {}", dest_host, dest_port, e)
            self._send_failure_reply(client_writer, ReplyCode.GENERAL_FAILURE)

        except Exception as e:
            logger.error("MITM error for {}:{}: {}", dest_host, dest_port, e)
            self._send_failure_reply(client_writer, ReplyCode.GENERAL_FAILURE)

    async def _connect_to_destination(
        self, dest_host: str, dest_port: int
    ) -> tuple:
        """Establish a verified TLS connection to the real destination.

        Creates a secure TLS context that validates the server's
        certificate, ensuring we're connecting to the legitimate server.

        Args:
            dest_host: Destination hostname.
            dest_port: Destination TCP port.

        Returns:
            A tuple of (reader, writer) for the TLS connection.
        """
        # Create TLS context as a client — verify the real server's cert
        dest_context = ssl.create_default_context()
        dest_context.check_hostname = True
        dest_context.verify_mode = ssl.CERT_REQUIRED

        return await asyncio.open_connection(
            dest_host, dest_port, ssl=dest_context
        )

    async def _upgrade_client_tls(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        hostname: str,
        cert_path: str,
        key_path: str,
    ) -> tuple:
        """Upgrade the client connection to TLS using our generated certificate.

        After the SOCKS5 CONNECT reply, the client will initiate a TLS
        handshake. We intercept this by acting as the TLS server,
        presenting our CA-signed certificate for the destination domain.

        Args:
            reader: Existing StreamReader for the client.
            writer: Existing StreamWriter for the client.
            hostname: The hostname for SNI matching.
            cert_path: Path to the generated certificate PEM file.
            key_path: Path to the generated private key PEM file.

        Returns:
            A tuple of (tls_reader, tls_writer) for the encrypted connection.
        """
        # Create server-side TLS context with our generated cert
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        # Start TLS on the existing connection
        # The client will see our certificate (signed by our CA)
        transport = writer.transport
        protocol = transport.get_protocol()

        new_transport = await asyncio.wait_for(
            loop_start_tls(
                transport, protocol, client_context, server_side=True
            ),
            timeout=self.connection_timeout,
        )

        # Create new reader/writer for the TLS connection
        tls_reader = asyncio.StreamReader()
        tls_protocol = asyncio.StreamReaderProtocol(tls_reader)
        new_transport.set_protocol(tls_protocol)

        tls_writer = asyncio.StreamWriter(
            new_transport, tls_protocol, tls_reader, None
        )

        return tls_reader, tls_writer

    async def _relay_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
    ) -> None:
        """Relay data between TLS streams with optional modification.

        This is where traffic inspection or modification hooks could be
        added. Currently, it performs a simple byte relay, but the
        architecture supports adding interceptors for specific protocols.

        Args:
            reader: Source TLS stream to read from.
            writer: Destination TLS stream to write to.
            direction: Label for logging (e.g., "client->dest").
        """
        try:
            while True:
                data = await reader.read(self.buffer_size)
                if not data:
                    break

                # TODO: Add traffic modification hooks here
                # For now, simple transparent relay
                writer.write(data)
                await writer.drain()

        except asyncio.CancelledError:
            pass
        except ssl.SSLError as e:
            logger.debug("TLS error in direction {}: {}", direction, e)
        except ConnectionResetError:
            logger.debug("Connection reset in direction: {}", direction)
        except BrokenPipeError:
            logger.debug("Broken pipe in direction: {}", direction)
        except OSError as e:
            logger.debug("I/O error in direction {}: {}", direction, e)
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
            except Exception:
                pass

    @staticmethod
    def _send_failure_reply(writer: asyncio.StreamWriter, code: ReplyCode) -> None:
        """Send a SOCKS5 failure reply if the connection hasn't been replied to yet.

        This is a best-effort send — if the writer is already closed,
        we silently ignore the error since the client has already disconnected.

        Args:
            writer: Client StreamWriter.
            code: SOCKS5 error reply code.
        """
        try:
            reply = Socks5Handshake.build_reply(code)
            writer.write(reply)
            writer.drain()
        except Exception:
            pass


async def loop_start_tls(transport, protocol, ssl_context, server_side=True):
    """Helper to perform TLS upgrade on an existing asyncio transport.

    This wraps the event loop's start_tls method to upgrade a plain
    TCP connection to TLS. This is necessary because asyncio doesn't
    provide a high-level API for TLS upgrade on server-side connections.

    Args:
        transport: The existing TCP transport.
        protocol: The existing protocol instance.
        ssl_context: SSL context for the TLS connection.
        server_side: Whether this is a server-side TLS (True for MITM).

    Returns:
        The new TLS transport.
    """
    loop = asyncio.get_event_loop()
    return await loop.start_tls(
        transport, protocol, ssl_context, server_side=server_side
    )
