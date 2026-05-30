"""
Proxy Router - Decision Engine for Connection Handling.

Routes incoming SOCKS5 connections to either the TCP Tunnel or the
MITM Proxy based on the domain classification result. This is the
central dispatch point that implements LocalBridge's core innovation:
selective MITM based on certificate pinning detection.

For pinned domains → TCP Tunnel (transparent relay, no TLS inspection)
For non-pinned domains → MITM Proxy (TLS interception with CA-signed certs)
"""

import asyncio
from typing import Optional

from loguru import logger

from ..config import Config
from ..classifier.domain import DomainClassifier
from ..socks5.handshake import Socks5Request, Socks5Handshake, ReplyCode
from .tunnel import TCPTunnel
from .mitm import MITMProxy
from ..certificate.ca import CertificateAuthority
from ..certificate.generator import CertificateGenerator
from ..utils.network import reverse_dns


class ProxyRouter:
    """Routes SOCKS5 connections to tunnel or MITM based on domain classification.

    This router is the bridge between the SOCKS5 server and the proxy
    handlers. For each incoming connection, it:
    1. Determines the destination domain (from SOCKS5 request or reverse DNS)
    2. Classifies the domain as pinned or non-pinned
    3. Routes to the appropriate handler

    Attributes:
        classifier: Domain classifier for pinning detection.
        tunnel: TCP tunnel handler for pinned connections.
        mitm: MITM proxy handler for non-pinned connections.
    """

    def __init__(self, classifier: DomainClassifier, config: Config):
        """Initialize the router with all required components.

        Sets up the CA, certificate generator, tunnel, and MITM proxy
        based on the application configuration.

        Args:
            classifier: DomainClassifier instance for pinning decisions.
            config: Full application configuration.
        """
        self.config = config
        self.classifier = classifier

        # Initialize Certificate Authority
        self.ca = CertificateAuthority(
            ca_cert_path=config.certificate.ca_path,
            ca_key_path=config.certificate.ca_key_path,
        )
        self.ca.initialize()

        # Initialize Certificate Generator
        self.cert_generator = CertificateGenerator(
            ca_cert=self.ca.ca_cert,
            ca_key=self.ca.ca_key,
            cache_dir=config.certificate.cert_cache_dir,
            validity_days=config.certificate.cert_validity_days,
        )

        # Initialize proxy handlers
        self.tunnel = TCPTunnel(config)
        self.mitm = MITMProxy(self.cert_generator, config)

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: Socks5Request,
    ) -> None:
        """Route a SOCKS5 connection to the appropriate handler.

        Determines the destination domain (using reverse DNS if necessary),
        classifies it, and delegates to either the TCP tunnel or MITM proxy.

        Args:
            reader: Client StreamReader.
            writer: Client StreamWriter.
            request: Parsed SOCKS5 connection request.
        """
        dest_host = request.dest_host
        dest_port = request.dest_port

        logger.debug(
            "Routing connection to {}:{} (atyp={})",
            dest_host,
            dest_port,
            request.atyp,
        )

        # If client connected by IP, try reverse DNS for better classification
        classification_host = dest_host
        if request.atyp == 0x01:  # IPv4
            # Attempt reverse DNS to get the actual domain name
            resolved = reverse_dns(dest_host)
            if resolved:
                classification_host = resolved
                logger.debug(
                    "Reverse DNS: {} -> {}", dest_host, resolved
                )

        # Classify the destination
        is_pinned = self.classifier.is_pinned(classification_host, dest_port)

        if is_pinned:
            logger.info(
                "PINNED: {}:{} → TCP Tunnel (no MITM)",
                dest_host,
                dest_port,
            )
            await self.tunnel.relay(reader, writer, dest_host, dest_port)
        else:
            logger.info(
                "NON-PINNED: {}:{} → MITM Proxy (intercept)",
                dest_host,
                dest_port,
            )
            await self.mitm.relay(reader, writer, dest_host, dest_port)
