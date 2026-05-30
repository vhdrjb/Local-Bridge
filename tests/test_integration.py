"""
Integration Tests for LocalBridge.

Tests the full system integration including server startup,
CA generation, classifier + router integration, and SOCKS5 handshake.
"""

import asyncio
import os
import tempfile
import pytest
import yaml

from localbridge.config import Config
from localbridge.certificate.ca import CertificateAuthority
from localbridge.certificate.generator import CertificateGenerator
from localbridge.classifier.domain import DomainClassifier
from localbridge.proxy.router import ProxyRouter
from localbridge.socks5.server import SOCKS5Server
from localbridge.socks5.handshake import Socks5Handshake, ReplyCode, ATYP_IPV4


class TestCAIntegration:
    """Integration tests for Certificate Authority."""

    def test_ca_generation_and_loading(self):
        """CA should generate correctly and be loadable afterward."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "ca.pem")
            key_path = os.path.join(tmpdir, "ca-key.pem")

            # Generate new CA
            ca = CertificateAuthority(cert_path, key_path)
            ca.initialize()

            assert ca.ca_cert is not None
            assert ca.ca_key is not None
            assert os.path.exists(cert_path)
            assert os.path.exists(key_path)

            # Load existing CA
            ca2 = CertificateAuthority(cert_path, key_path)
            ca2.initialize()

            assert ca2.ca_cert is not None
            assert ca2.ca_key is not None
            # Same serial number means same cert
            assert ca.ca_cert.serial_number == ca2.ca_cert.serial_number

    def test_ca_pem_export(self):
        """CA should be exportable as PEM string."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "ca.pem")
            key_path = os.path.join(tmpdir, "ca-key.pem")

            ca = CertificateAuthority(cert_path, key_path)
            ca.initialize()

            pem = ca.get_ca_pem()
            assert "BEGIN CERTIFICATE" in pem
            assert "END CERTIFICATE" in pem


class TestCertGeneratorIntegration:
    """Integration tests for Certificate Generator."""

    def test_generate_cert_for_domain(self):
        """Should generate and cache a certificate for a domain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "ca.pem")
            key_path = os.path.join(tmpdir, "ca-key.pem")
            cache_dir = os.path.join(tmpdir, "cache")

            ca = CertificateAuthority(cert_path, key_path)
            ca.initialize()

            generator = CertificateGenerator(
                ca_cert=ca.ca_cert,
                ca_key=ca.ca_key,
                cache_dir=cache_dir,
            )

            # Generate cert for a domain
            domain_cert, domain_key = generator.generate_cert("example.com")
            assert os.path.exists(domain_cert)
            assert os.path.exists(domain_key)

            # Second call should return cached cert
            domain_cert2, domain_key2 = generator.generate_cert("example.com")
            assert domain_cert == domain_cert2

    def test_generate_multiple_domains(self):
        """Should generate separate certs for different domains."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "ca.pem")
            key_path = os.path.join(tmpdir, "ca-key.pem")
            cache_dir = os.path.join(tmpdir, "cache")

            ca = CertificateAuthority(cert_path, key_path)
            ca.initialize()

            generator = CertificateGenerator(
                ca_cert=ca.ca_cert,
                ca_key=ca.ca_key,
                cache_dir=cache_dir,
            )

            cert1, _ = generator.generate_cert("example.com")
            cert2, _ = generator.generate_cert("other.com")
            assert cert1 != cert2
            assert generator.cache_size() == 2


class TestRouterIntegration:
    """Integration tests for the ProxyRouter with classifier."""

    def _make_config(self, tmpdir: str) -> Config:
        """Create a test configuration with temporary directories."""
        # Create pinned domains YAML
        yaml_path = os.path.join(tmpdir, "pinned.yaml")
        with open(yaml_path, "w") as f:
            yaml.dump({"pinned_domains": ["*.telegram.org", "github.com"]}, f)

        config = Config()
        config.pinned_domains.config_file = yaml_path
        config.pinned_domains.user_override_file = os.path.join(tmpdir, "no-overrides.txt")
        config.certificate.ca_path = os.path.join(tmpdir, "ca.pem")
        config.certificate.ca_key_path = os.path.join(tmpdir, "ca-key.pem")
        config.certificate.cert_cache_dir = os.path.join(tmpdir, "cache")
        return config

    def test_router_initializes_ca(self):
        """Router should initialize CA during construction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._make_config(tmpdir)
            classifier = DomainClassifier(config)
            router = ProxyRouter(classifier, config)

            assert router.ca.ca_cert is not None
            assert router.ca.ca_key is not None
            assert os.path.exists(config.certificate.ca_path)

    def test_router_has_tunnel_and_mitm(self):
        """Router should have both tunnel and MITM handlers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._make_config(tmpdir)
            classifier = DomainClassifier(config)
            router = ProxyRouter(classifier, config)

            assert router.tunnel is not None
            assert router.mitm is not None


class TestSocks5HandshakeUnit:
    """Unit tests for SOCKS5 handshake message building."""

    def test_build_success_reply(self):
        """Should build a valid SOCKS5 success reply."""
        reply = Socks5Handshake.build_reply(ReplyCode.SUCCEEDED)
        # VER=0x05, REP=0x00, RSV=0x00, ATYP=0x01, 4 bytes IP, 2 bytes port
        assert len(reply) == 10
        assert reply[0] == 0x05  # SOCKS5 version
        assert reply[1] == 0x00  # Success

    def test_build_failure_reply(self):
        """Should build a valid SOCKS5 failure reply."""
        reply = Socks5Handshake.build_reply(ReplyCode.CONNECTION_REFUSED)
        assert reply[1] == 0x05  # Connection refused code

    def test_build_reply_with_custom_address(self):
        """Should include bind address and port in reply."""
        reply = Socks5Handshake.build_reply(
            ReplyCode.SUCCEEDED,
            bind_address="127.0.0.1",
            bind_port=8080,
        )
        # Last 2 bytes should be port 8080 in network byte order
        import struct
        port = struct.unpack("!H", reply[-2:])[0]
        assert port == 8080
