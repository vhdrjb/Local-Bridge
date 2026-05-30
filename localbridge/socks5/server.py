"""
SOCKS5 Server Implementation.

The main entry point for incoming SOCKS5 connections. Listens on a
configurable port, accepts client connections, performs the SOCKS5
handshake, and routes successfully negotiated connections to the
appropriate proxy handler (tunnel or MITM).

This server uses Python's asyncio for concurrent connection handling,
enabling it to manage thousands of simultaneous connections efficiently.
"""

import asyncio
from typing import Optional

from loguru import logger

from .auth import AuthHandler
from .handshake import Socks5Handshake, ReplyCode, ATYP_IPV4
from ..config import Config
from ..utils.logger import get_access_logger


class SOCKS5Server:
    """Async SOCKS5 proxy server.

    Listens for incoming SOCKS5 connections, performs protocol handshakes,
    and delegates each connection to the proxy router for processing.

    The server manages a connection counter for monitoring and enforces
    the maximum connection limit from configuration.

    Attributes:
        host: Bind address for the listening socket.
        port: Bind port for the listening socket.
        config: Full application configuration.
        router: Proxy router for handling connections after handshake.
        auth_handler: Authentication handler for method negotiation.
    """

    def __init__(self, host: str, port: int, router, config: Config):
        """Initialize the SOCKS5 server.

        Args:
            host: Network interface to bind to (e.g., "0.0.0.0" for all).
            port: TCP port to listen on (default SOCKS5 port is 1080).
            router: ProxyRouter instance that handles tunneled/MITM connections.
            config: Application configuration for auth, performance, etc.
        """
        self.host = host
        self.port = port
        self.config = config
        self.router = router
        self.auth_handler = AuthHandler(
            enabled=config.auth.enabled,
            username=config.auth.username,
            password=config.auth.password,
        )
        self.handshake = Socks5Handshake(self.auth_handler)
        self._server: Optional[asyncio.Server] = None
        self._active_connections = 0
        self._total_connections = 0
        self._shutdown_event = asyncio.Event()

    async def start(self) -> None:
        """Start the SOCKS5 server and begin accepting connections.

        Creates an asyncio TCP server that handles each connection
        in a separate task. The server runs until stop() is called
        or a shutdown signal is received.
        """
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
        )

        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        logger.info("LocalBridge SOCKS5 server listening on {}", addrs)
        logger.info(
            "Configure devices to use SOCKS5 proxy at {}:{}",
            self.host if self.host != "0.0.0.0" else "<your-ip>",
            self.port,
        )

        # Wait until shutdown is requested
        await self._shutdown_event.wait()

    async def stop(self) -> None:
        """Gracefully stop the SOCKS5 server.

        Closes the listening socket and waits for active connections
        to finish. Signals the shutdown event to unblock the start() method.
        """
        logger.info("Stopping SOCKS5 server...")
        self._shutdown_event.set()

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        logger.info(
            "Server stopped. Total connections served: {}", self._total_connections
        )

    async def _handle_connection(self, reader, writer) -> None:
        """Handle a single SOCKS5 client connection.

        This is the main per-connection handler invoked by asyncio for
        each new TCP connection. It performs the full SOCKS5 lifecycle:
        1. Method negotiation
        2. Request parsing
        3. Delegation to the proxy router
        4. Cleanup on disconnect

        Args:
            reader: asyncio StreamReader for the client connection.
            writer: asyncio StreamWriter for the client connection.
        """
        peer = writer.get_extra_info("peername")
        logger.debug("New connection from {}", peer)

        # Enforce maximum connection limit
        if self._active_connections >= self.config.server.max_connections:
            logger.warning(
                "Connection rejected from {} — max connections ({}) reached",
                peer,
                self.config.server.max_connections,
            )
            writer.close()
            return

        self._active_connections += 1
        self._total_connections += 1

        try:
            # Phase 1: Method negotiation
            if not await self.handshake.negotiate_method(reader, writer):
                logger.warning("Handshake failed for {}", peer)
                return

            # Phase 2: Parse the SOCKS5 request
            request = await self.handshake.parse_request(reader)
            if request is None:
                logger.warning("Invalid request from {}", peer)
                failure_reply = self.handshake.build_reply(
                    ReplyCode.GENERAL_FAILURE
                )
                writer.write(failure_reply)
                await writer.drain()
                return

            # Log the connection for access auditing
            access_logger = get_access_logger()
            access_logger.info(
                "CONNECT {}:{} (atyp={}) from {}",
                request.dest_host,
                request.dest_port,
                request.atyp,
                peer,
            )

            # Phase 3: Delegate to the proxy router
            await self.router.handle_connection(reader, writer, request)

        except ConnectionResetError:
            logger.debug("Connection reset by {}", peer)
        except asyncio.IncompleteReadError:
            logger.debug("Incomplete read from {} — client disconnected", peer)
        except Exception as e:
            logger.error("Error handling connection from {}: {}", peer, e)
        finally:
            self._active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug(
                "Connection closed from {} (active: {})",
                peer,
                self._active_connections,
            )

    @property
    def active_connections(self) -> int:
        """Return the number of currently active connections."""
        return self._active_connections

    @property
    def total_connections(self) -> int:
        """Return the total number of connections served since startup."""
        return self._total_connections
