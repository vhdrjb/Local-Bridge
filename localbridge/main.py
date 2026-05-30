"""
LocalBridge - Main Entry Point.

Starts the selective MITM SOCKS5 proxy server. This module orchestrates
all components: configuration loading, logging setup, domain classification,
certificate management, and the SOCKS5 server lifecycle.

Usage:
    python -m localbridge                    # Run with defaults
    python -m localbridge --config path.conf # Run with custom config
    localbridge                              # Via console_scripts entry point
"""

import asyncio
import argparse
import signal
import sys
import os
from pathlib import Path

from loguru import logger

from .config import Config
from .socks5.server import SOCKS5Server
from .classifier.domain import DomainClassifier
from .proxy.router import ProxyRouter
from .utils.logger import setup_logging
from .utils.network import get_local_ip


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Namespace with config path and optional overrides.
    """
    parser = argparse.ArgumentParser(
        description="LocalBridge - Selective MITM Proxy with SOCKS5",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  localbridge                          # Start with defaults\n"
            "  localbridge --config /path/to.conf   # Custom configuration\n"
            "  localbridge --port 9050              # Override port\n"
        ),
    )
    parser.add_argument(
        "--config", "-c",
        default="config/localbridge.conf",
        help="Path to configuration file (default: config/localbridge.conf)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Override SOCKS5 listening port (default: from config or 1080)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override bind address (default: from config or 0.0.0.0)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level (default: from config or INFO)",
    )
    parser.add_argument(
        "--init-ca",
        action="store_true",
        help="Generate CA certificate and exit (useful for first-time setup)",
    )
    return parser.parse_args()


async def create_server(config: Config) -> SOCKS5Server:
    """Create and configure the SOCKS5 server with all dependencies.

    Initializes the domain classifier, proxy router (which in turn
    initializes the CA and certificate generator), and the SOCKS5 server.

    Args:
        config: Application configuration.

    Returns:
        A fully configured SOCKS5Server ready to start.
    """
    # Initialize domain classifier
    classifier = DomainClassifier(config)

    # Initialize proxy router (includes CA setup)
    router = ProxyRouter(classifier, config)

    # Create SOCKS5 server
    server = SOCKS5Server(
        host=config.server.host,
        port=config.server.port,
        router=router,
        config=config,
    )

    return server


async def run_server(config: Config) -> None:
    """Run the SOCKS5 server with graceful shutdown support.

    Sets up signal handlers for SIGINT and SIGTERM to trigger
    graceful shutdown, then starts the server event loop.

    Args:
        config: Application configuration.
    """
    server = await create_server(config)

    # Setup graceful shutdown handlers
    loop = asyncio.get_running_loop()

    def signal_handler():
        logger.info("Shutdown signal received")
        asyncio.create_task(server.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            # Fallback: just let KeyboardInterrupt propagate
            pass

    # Print startup banner
    _print_banner(config)

    # Start serving
    await server.start()


def _print_banner(config: Config) -> None:
    """Print a startup banner with configuration summary.

    Shows the user how to configure their devices to use the proxy.

    Args:
        config: Application configuration.
    """
    local_ip = get_local_ip()
    port = config.server.port

    logger.info("=" * 60)
    logger.info("  LocalBridge - Selective MITM SOCKS5 Proxy")
    logger.info("=" * 60)
    logger.info("  Listening:     {}:{}", config.server.host, port)
    logger.info("  Local IP:      {}", local_ip)
    logger.info("  SOCKS5 Proxy:  {}:{}", local_ip, port)
    logger.info("  Auth:          {}", "Enabled" if config.auth.enabled else "Disabled")
    logger.info("  CA Certificate: {}", config.certificate.ca_path)
    logger.info("=" * 60)
    logger.info("  Configure your device SOCKS5 proxy:")
    logger.info("    Server: {}", local_ip)
    logger.info("    Port:   {}", port)
    logger.info("  Import CA cert on device: {}", config.certificate.ca_path)
    logger.info("=" * 60)


def run() -> None:
    """Main entry point called by the console_scripts entry point.

    Loads configuration, initializes components, and runs the server.
    Handles keyboard interrupts and other errors gracefully.
    """
    args = parse_args()

    # Load configuration
    try:
        if os.path.exists(args.config):
            config = Config.load(args.config)
        else:
            logger.warning(
                "Config file not found at '{}', using defaults",
                args.config,
            )
            config = Config.from_defaults()
    except Exception as e:
        logger.error("Failed to load configuration: {}", e)
        sys.exit(1)

    # Apply command-line overrides
    if args.port is not None:
        config.server.port = args.port
    if args.host is not None:
        config.server.host = args.host
    if args.log_level is not None:
        config.logging.level = args.log_level

    # Ensure required directories exist
    config.ensure_directories()

    # Setup logging
    setup_logging(
        level=config.logging.level,
        log_file=config.logging.log_file,
        access_log=config.logging.access_log,
    )

    # Handle --init-ca flag
    if args.init_ca:
        from .certificate.ca import CertificateAuthority

        ca = CertificateAuthority(
            ca_cert_path=config.certificate.ca_path,
            ca_key_path=config.certificate.ca_key_path,
        )
        ca.initialize()
        logger.info("CA certificate generated at: {}", config.certificate.ca_path)
        logger.info("CA private key generated at: {}", config.certificate.ca_key_path)
        logger.info("Import the CA certificate on your devices to enable MITM.")
        return

    # Run the server
    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error("Server error: {}", e)
        sys.exit(1)


if __name__ == "__main__":
    run()
