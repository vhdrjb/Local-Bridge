"""
Certificate Authority Management.

Generates and manages the root CA certificate and private key used
by LocalBridge to sign dynamically generated per-domain certificates.
The CA certificate must be imported on client devices for the MITM
proxy to work with HTTPS connections.

This module handles:
- One-time CA generation (if not already present)
- Loading existing CA certificate and key
- CA certificate metadata (subject, validity, extensions)
"""

import os
import datetime
from pathlib import Path
from typing import Tuple, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from loguru import logger


# CA certificate defaults
CA_KEY_SIZE = 2048
CA_VALIDITY_YEARS = 10
CA_COMMON_NAME = "LocalBridge CA"
CA_ORGANIZATION = "LocalBridge"
CA_COUNTRY = "US"


class CertificateAuthority:
    """Manages the root Certificate Authority for MITM certificate signing.

    The CA is the trust anchor for all dynamically generated certificates.
    Its public certificate must be installed on client devices, while the
    private key must be kept secure on the proxy machine.

    Attributes:
        ca_cert_path: File path to the CA certificate (PEM format).
        ca_key_path: File path to the CA private key (PEM format).
        ca_cert: Loaded CA certificate object (None until initialized).
        ca_key: Loaded CA private key object (None until initialized).
    """

    def __init__(self, ca_cert_path: str, ca_key_path: str):
        """Initialize with paths for CA certificate and key files.

        Args:
            ca_cert_path: Where to store/load the CA certificate.
            ca_key_path: Where to store/load the CA private key.
        """
        self.ca_cert_path = os.path.expanduser(ca_cert_path)
        self.ca_key_path = os.path.expanduser(ca_key_path)
        self.ca_cert: Optional[x509.Certificate] = None
        self.ca_key: Optional[rsa.RSAPrivateKey] = None

    def initialize(self) -> None:
        """Load existing CA or generate a new one if not present.

        This is the main entry point called during proxy startup.
        If both the certificate and key files exist, they are loaded.
        If either is missing, a new CA is generated and saved.
        """
        if self._ca_files_exist():
            self._load_ca()
            logger.info("Loaded existing CA from {}", self.ca_cert_path)
        else:
            self._generate_ca()
            logger.info("Generated new CA at {}", self.ca_cert_path)
            logger.info(
                "IMPORTANT: Import {} on client devices for MITM to work",
                self.ca_cert_path,
            )

    def _ca_files_exist(self) -> bool:
        """Check if both CA certificate and key files exist."""
        return os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path)

    def _load_ca(self) -> None:
        """Load CA certificate and key from existing files.

        Raises:
            FileNotFoundError: If files exist but cannot be read.
            ValueError: If files contain invalid PEM data.
        """
        try:
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())

            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)

            logger.debug("CA certificate subject: {}", self.ca_cert.subject)

        except Exception as e:
            logger.error("Failed to load CA: {}", e)
            raise

    def _generate_ca(self) -> None:
        """Generate a new root CA certificate and private key.

        Creates a self-signed CA certificate with:
        - RSA 2048-bit key
        - 10-year validity period
        - Basic Constraints: CA=True (critical)
        - Key Usage: certificate signing, CRL signing
        - Subject Key Identifier and Authority Key Identifier

        The generated files are saved in PEM format for easy import.
        """
        # Ensure directory exists
        Path(self.ca_cert_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.ca_key_path).parent.mkdir(parents=True, exist_ok=True)

        # Generate RSA private key
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=CA_KEY_SIZE,
        )

        # Build CA certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        ])

        # Build and sign the certificate
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=CA_VALIDITY_YEARS * 365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False,
            )
        )

        self.ca_cert = builder.sign(self.ca_key, hashes.SHA256())

        # Save certificate to PEM file
        cert_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM)
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert_pem)
        os.chmod(self.ca_cert_path, 0o644)

        # Save private key to PEM file (restrictive permissions)
        key_pem = self.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self.ca_key_path, "wb") as f:
            f.write(key_pem)
        os.chmod(self.ca_key_path, 0o600)  # Only owner can read

        logger.info("CA certificate saved to {}", self.ca_cert_path)
        logger.info("CA private key saved to {} (permissions: 600)", self.ca_key_path)

    def get_ca_pem(self) -> str:
        """Return the CA certificate as a PEM-encoded string.

        Useful for displaying to the user or transferring to client devices.

        Returns:
            The CA certificate in PEM format as a string.

        Raises:
            RuntimeError: If the CA has not been initialized.
        """
        if self.ca_cert is None:
            raise RuntimeError("CA not initialized — call initialize() first")
        return self.ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
