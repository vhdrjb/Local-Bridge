"""
Configuration Management for LocalBridge.

Loads and validates configuration from INI files, providing typed access
to all proxy settings including server, authentication, certificates,
pinned domains, logging, and performance parameters.

Supports environment variable overrides for sensitive values.
"""

import os
import configparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ServerConfig:
    """SOCKS5 server binding and connection settings."""

    host: str = "0.0.0.0"
    port: int = 1080
    max_connections: int = 1000


@dataclass
class AuthConfig:
    """SOCKS5 authentication configuration.

    When enabled, clients must provide username/password.
    Disabled by default for trusted local network usage.
    """

    enabled: bool = False
    username: str = ""
    password: str = ""


@dataclass
class CertificateConfig:
    """TLS certificate authority and dynamic cert generation settings.

    The CA certificate must be imported on client devices for MITM to work.
    Generated certificates are cached to avoid repeated signing operations.
    """

    ca_path: str = "./certs/ca.pem"
    ca_key_path: str = "./certs/ca-key.pem"
    cert_cache_dir: str = "./certs/cache"
    cert_validity_days: int = 365


@dataclass
class PinnedDomainsConfig:
    """Pinned domains configuration paths.

    Pinned domains are never intercepted — traffic is tunneled transparently
    so that certificate-pinned applications see legitimate certificates.
    """

    config_file: str = "./config/pinned_domains.yaml"
    user_override_file: str = "~/.localbridge/pinned_domains.txt"


@dataclass
class LoggingConfig:
    """Logging configuration for runtime diagnostics and access tracking."""

    level: str = "INFO"
    log_file: str = "./logs/localbridge.log"
    access_log: str = "./logs/access.log"


@dataclass
class PerformanceConfig:
    """Performance tuning parameters for relay throughput and connection lifecycle."""

    buffer_size: int = 8192
    connection_timeout: int = 30
    idle_timeout: int = 300


@dataclass
class Config:
    """Top-level configuration container aggregating all sub-configs.

    Loaded from an INI file via Config.load() or created with defaults.
    """

    server: ServerConfig = field(default_factory=ServerConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    certificate: CertificateConfig = field(default_factory=CertificateConfig)
    pinned_domains: PinnedDomainsConfig = field(default_factory=PinnedDomainsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)

    @classmethod
    def load(cls, config_path: str) -> "Config":
        """Load configuration from an INI file.

        Falls back to defaults for any missing sections or keys,
        ensuring the proxy can start even with a partial config file.

        Args:
            config_path: Path to the INI configuration file.

        Returns:
            A fully populated Config instance.

        Raises:
            FileNotFoundError: If the config file path does not exist.
        """
        config_path = os.path.expanduser(config_path)
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        parser = configparser.ConfigParser()
        parser.read(config_path)

        server = ServerConfig(
            host=parser.get("server", "host", fallback=cls.server.host),
            port=parser.getint("server", "port", fallback=cls.server.port),
            max_connections=parser.getint(
                "server", "max_connections", fallback=cls.server.max_connections
            ),
        )

        auth = AuthConfig(
            enabled=parser.getboolean(
                "authentication", "enabled", fallback=cls.auth.enabled
            ),
            username=parser.get(
                "authentication", "username", fallback=cls.auth.username
            ),
            password=os.environ.get(
                "LOCALBRIDGE_AUTH_PASSWORD",
                parser.get("authentication", "password", fallback=cls.auth.password),
            ),
        )

        certificate = CertificateConfig(
            ca_path=parser.get(
                "certificate", "ca_path", fallback=cls.certificate.ca_path
            ),
            ca_key_path=parser.get(
                "certificate", "ca_key_path", fallback=cls.certificate.ca_key_path
            ),
            cert_cache_dir=parser.get(
                "certificate", "cert_cache_dir", fallback=cls.certificate.cert_cache_dir
            ),
            cert_validity_days=parser.getint(
                "certificate",
                "cert_validity_days",
                fallback=cls.certificate.cert_validity_days,
            ),
        )

        pinned = PinnedDomainsConfig(
            config_file=parser.get(
                "pinned_domains", "config_file", fallback=cls.pinned_domains.config_file
            ),
            user_override_file=parser.get(
                "pinned_domains",
                "user_override_file",
                fallback=cls.pinned_domains.user_override_file,
            ),
        )

        logging_cfg = LoggingConfig(
            level=parser.get("logging", "level", fallback=cls.logging.level),
            log_file=parser.get("logging", "log_file", fallback=cls.logging.log_file),
            access_log=parser.get(
                "logging", "access_log", fallback=cls.logging.access_log
            ),
        )

        performance = PerformanceConfig(
            buffer_size=parser.getint(
                "performance", "buffer_size", fallback=cls.performance.buffer_size
            ),
            connection_timeout=parser.getint(
                "performance",
                "connection_timeout",
                fallback=cls.performance.connection_timeout,
            ),
            idle_timeout=parser.getint(
                "performance", "idle_timeout", fallback=cls.performance.idle_timeout
            ),
        )

        return cls(
            server=server,
            auth=auth,
            certificate=certificate,
            pinned_domains=pinned,
            logging=logging_cfg,
            performance=performance,
        )

    @classmethod
    def from_defaults(cls) -> "Config":
        """Create a configuration with all default values.

        Useful for quick-start scenarios where no config file exists yet.
        """
        return cls()

    def ensure_directories(self) -> None:
        """Create all required directories for logs, certificates, and cache.

        Called during startup to prevent file-not-found errors at runtime.
        """
        dirs = [
            Path(self.certificate.ca_path).parent,
            Path(self.certificate.cert_cache_dir),
            Path(self.logging.log_file).parent,
            Path(self.logging.access_log).parent,
            Path(self.pinned_domains.user_override_file).expanduser().parent,
        ]
        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)
