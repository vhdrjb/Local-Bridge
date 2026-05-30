"""
Dynamic Certificate Generator.

Generates per-domain TLS certificates signed by the LocalBridge CA.
These certificates are presented to clients during MITM interception,
allowing the proxy to decrypt and inspect HTTPS traffic for non-pinned
domains.

Generated certificates include:
- Subject matching the requested domain
- Subject Alternative Name (SAN) with domain and wildcard variant
- Standard TLS server extensions (key usage, extended key usage)
- Cached on disk to avoid repeated generation overhead
"""

import os
import hashlib
import datetime
from pathlib import Path
from typing import Tuple, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from loguru import logger


# Certificate generation defaults
CERT_KEY_SIZE = 2048
CERT_DEFAULT_VALIDITY_DAYS = 365
CERT_SERIAL_SEED = 1000


class CertificateGenerator:
    """Generates and caches per-domain TLS certificates signed by the CA.

    For each unique domain, a new RSA key pair and X.509 certificate is
    generated, signed by the LocalBridge CA. Certificates are cached on
    disk so they only need to be generated once per domain.

    Attributes:
        ca_cert: The CA certificate object used as the issuer.
        ca_key: The CA private key used for signing.
        cache_dir: Directory where generated certificates are cached.
        validity_days: Number of days generated certificates remain valid.
    """

    def __init__(
        self,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        cache_dir: str,
        validity_days: int = CERT_DEFAULT_VALIDITY_DAYS,
    ):
        """Initialize the certificate generator with CA credentials.

        Args:
            ca_cert: The CA certificate (used as issuer for generated certs).
            ca_key: The CA private key (used to sign generated certs).
            cache_dir: Directory path for certificate cache storage.
            validity_days: How long generated certificates remain valid.
        """
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.cache_dir = os.path.expanduser(cache_dir)
        self.validity_days = validity_days

        # Ensure cache directory exists
        Path(self.cache_dir).mkdir(parents=True, exist_ok=True)

        # In-memory cache to avoid disk reads for repeated domains
        self._memory_cache = {}

    def generate_cert(self, domain: str) -> Tuple[str, str]:
        """Generate or retrieve a cached certificate for the given domain.

        First checks the in-memory cache, then the disk cache. If no
        cached certificate exists, generates a new one, signs it with
        the CA, saves it to disk, and returns the file paths.

        Args:
            domain: The destination domain name (e.g., "example.com").

        Returns:
            A tuple of (cert_path, key_path) for the generated certificate.
        """
        # Normalize domain for consistent caching
        domain = domain.lower().rstrip(".")

        # Check in-memory cache
        if domain in self._memory_cache:
            return self._memory_cache[domain]

        # Check disk cache
        cache_key = self._domain_cache_key(domain)
        cert_path = os.path.join(self.cache_dir, f"{cache_key}.pem")
        key_path = os.path.join(self.cache_dir, f"{cache_key}-key.pem")

        if os.path.exists(cert_path) and os.path.exists(key_path):
            logger.debug("Loaded cached certificate for {}", domain)
            self._memory_cache[domain] = (cert_path, key_path)
            return cert_path, key_path

        # Generate new certificate
        cert_path, key_path = self._generate_new_cert(domain, cert_path, key_path)
        self._memory_cache[domain] = (cert_path, key_path)
        return cert_path, key_path

    def _generate_new_cert(
        self, domain: str, cert_path: str, key_path: str
    ) -> Tuple[str, str]:
        """Generate a new TLS certificate for the given domain.

        Creates an RSA key pair and X.509 certificate with:
        - Common Name set to the domain
        - SAN including both the domain and a wildcard variant
        - TLS server authentication key usage
        - Signed by the LocalBridge CA

        Args:
            domain: The domain name for the certificate.
            cert_path: Where to save the certificate PEM file.
            key_path: Where to save the private key PEM file.

        Returns:
            A tuple of (cert_path, key_path).
        """
        logger.debug("Generating new certificate for {}", domain)

        # Generate RSA key pair
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=CERT_KEY_SIZE,
        )

        # Build subject with the domain as Common Name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LocalBridge"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])

        # Build certificate
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=self.validity_days))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                    x509.DNSName(f"*.{domain}"),
                ]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_key.public_key()
                ),
                critical=False,
            )
        )

        # Sign with CA key
        cert = builder.sign(self.ca_key, hashes.SHA256())

        # Save certificate
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        with open(cert_path, "wb") as f:
            f.write(cert_pem)

        # Save private key
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(key_path, "wb") as f:
            f.write(key_pem)

        logger.debug("Certificate generated and cached for {}", domain)
        return cert_path, key_path

    @staticmethod
    def _domain_cache_key(domain: str) -> str:
        """Generate a filesystem-safe cache key from a domain name.

        Uses SHA-256 hash of the domain to create a unique, safe filename
        that avoids any filesystem issues with special characters in domains.

        Args:
            domain: The domain name to hash.

        Returns:
            A hex-encoded SHA-256 hash string suitable for use as a filename.
        """
        return hashlib.sha256(domain.encode("ascii")).hexdigest()[:32]

    def clear_cache(self) -> None:
        """Remove all cached certificates from disk and memory.

        Useful for testing or when the CA has been regenerated.
        """
        self._memory_cache.clear()

        cache_path = Path(self.cache_dir)
        for file in cache_path.glob("*.pem"):
            file.unlink()

        logger.info("Certificate cache cleared")

    def cache_size(self) -> int:
        """Return the number of cached certificates on disk."""
        cache_path = Path(self.cache_dir)
        return len(list(cache_path.glob("*.pem"))) // 2  # Each cert has 2 files
