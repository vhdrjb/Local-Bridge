"""
TCP Tunnel for Pinned Domains.

Provides transparent, zero-modification byte relay between the client
and the destination server. This is the critical path for certificate-
pinned applications — since we never touch the TLS layer, the client
sees the legitimate server certificate and the connection succeeds.

THE #1 RULE FOR PINNED DOMAINS: Never touch the TLS layer. Period.
No SSL context, no certificate inspection, no byte modification.
Just raw bidirectional TCP relay.
"""

import asyncio
from typing import Tuple

from loguru import logger

from ..config import Config
from ..socks5.handshake import Socks5Handshake, ReplyCode, ATYP_IPV4
from ..utils.logger import get_access_logger


class TCPTunnel:
    """Transparent TCP relay for certificate-pinned connections.

    When a domain is classified as pinned, this tunnel creates a raw
    TCP connection to the destination and relays bytes in both directions
    without any inspection or modification. This ensures that TLS
    handshakes pass through untouched and certificate-pinned apps
    continue to work correctly.

    Attributes:
        config: Application configuration for buffer sizes and timeouts.
    """

    def __init__(self, config: Config):
        """Initialize the TCP tunnel with performance settings.

        Args:
            config: Application configuration (uses buffer_size and timeouts).
        """
        self.buffer_size = config.performance.buffer_size
        self.connection_timeout = config.performance.connection_timeout
        self.idle_timeout = config.performance.idle_timeout

    async def relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        dest_host: str,
        dest_port: int,
    ) -> None:
        """Establish a transparent tunnel and relay bytes bidirectionally.

        This is the main entry point for tunneled connections. The flow:
        1. Connect to the destination over raw TCP (no TLS)
        2. Send SOCKS5 success reply to the client
        3. Relay bytes in both directions until either side disconnects

        CRITICAL: We do NOT use any SSL context here. The client's TLS
        handshake passes through as raw bytes to the real server.

        Args:
            client_reader: StreamReader for the SOCKS5 client.
            client_writer: StreamWriter for the SOCKS5 client.
            dest_host: Destination hostname or IP address.
            dest_port: Destination TCP port number.
        """
        dest_reader = None
        dest_writer = None

        try:
            # Step 1: Connect to destination — RAW TCP, no SSL
            dest_reader, dest_writer = await asyncio.wait_for(
                asyncio.open_connection(dest_host, dest_port),
                timeout=self.connection_timeout,
            )

            # Step 2: Send SOCKS5 success reply
            reply = Socks5Handshake.build_reply(
                ReplyCode.SUCCEEDED,
                bind_address="0.0.0.0",
                bind_port=0,
                atyp=ATYP_IPV4,
            )
            client_writer.write(reply)
            await client_writer.drain()

            logger.info(
                "TCP tunnel established: {}:{} -> {}",
                dest_host,
                dest_port,
                "direct",
            )

            # Log to access log
            access_logger = get_access_logger()
            access_logger.info(
                "TUNNEL {}:{} (pinned, no MITM)",
                dest_host,
                dest_port,
            )

            # Step 3: Bidirectional relay — raw bytes, zero modification
            await asyncio.gather(
                self._relay_stream(
                    client_reader, dest_writer, "client->dest"
                ),
                self._relay_stream(
                    dest_reader, client_writer, "dest->client"
                ),
                return_exceptions=True,
            )

        except asyncio.TimeoutError:
            logger.warning("Connection timeout to {}:{}", dest_host, dest_port)
            failure_reply = Socks5Handshake.build_reply(
                ReplyCode.TTL_EXPIRED
            )
            try:
                client_writer.write(failure_reply)
                await client_writer.drain()
            except Exception:
                pass

        except ConnectionRefusedError:
            logger.warning("Connection refused by {}:{}", dest_host, dest_port)
            failure_reply = Socks5Handshake.build_reply(
                ReplyCode.CONNECTION_REFUSED
            )
            try:
                client_writer.write(failure_reply)
                await client_writer.drain()
            except Exception:
                pass

        except OSError as e:
            logger.error("Network error connecting to {}:{}: {}", dest_host, dest_port, e)
            failure_reply = Socks5Handshake.build_reply(
                ReplyCode.HOST_UNREACHABLE
            )
            try:
                client_writer.write(failure_reply)
                await client_writer.drain()
            except Exception:
                pass

        finally:
            # Clean up destination connection
            if dest_writer:
                try:
                    dest_writer.close()
                    await dest_writer.wait_closed()
                except Exception:
                    pass

    async def _relay_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
    ) -> None:
        """Relay data from one stream to another.

        Reads chunks of data from the source and writes them to the
        destination until the source is exhausted or an error occurs.
        This is a low-level byte relay — no protocol awareness needed.

        Args:
            reader: Source stream to read from.
            writer: Destination stream to write to.
            direction: Label for logging (e.g., "client->dest").
        """
        try:
            while True:
                data = await reader.read(self.buffer_size)
                if not data:
                    # Source closed — signal end of data
                    break
                writer.write(data)
                await writer.drain()

        except asyncio.CancelledError:
            # Task was cancelled — expected during shutdown
            pass

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
