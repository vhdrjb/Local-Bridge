"""
Domain Classification Engine.

Determines whether a given destination should be tunneled (pinned)
or intercepted (non-pinned). This is the core decision point that
enables LocalBridge's selective MITM capability.

Classification is performed by checking:
1. Exact domain match against the pinned list
2. Wildcard pattern match (e.g., *.telegram.org)
3. IP range match for connections resolved to known IP blocks
4. User-configured override entries

If none of these checks match, the domain is classified as non-pinned
and will be eligible for MITM interception.
"""

from typing import Optional

from loguru import logger

from .pinned_list import PinnedList, PinnedListLoader
from ..config import Config
from ..utils.network import resolve_domain, ip_in_range


class DomainClassifier:
    """Classifies destinations as pinned (tunnel) or non-pinned (MITM).

    The classifier loads the pinned domains database at initialization
    and provides a simple boolean decision interface. It also supports
    DNS-based IP range checking for services like Telegram that use
    well-known IP blocks.

    Attributes:
        pinned_list: The loaded and merged pinned domains database.
    """

    def __init__(self, config: Config):
        """Initialize the classifier with the pinned domains database.

        Loads both the default YAML configuration and any user overrides,
        merging them into a single lookup structure.

        Args:
            config: Application configuration containing pinned domain paths.
        """
        loader = PinnedListLoader(
            config_file=config.pinned_domains.config_file,
            user_override_file=config.pinned_domains.user_override_file,
        )
        self.pinned_list = loader.load()

    def is_pinned(self, domain: str, port: int = 0) -> bool:
        """Determine if a destination should be tunneled (pinned).

        Checks the domain against all pinned entry types in order:
        exact match → wildcard match → IP range match.

        The port parameter is available for future use (e.g., pinning
        specific ports on otherwise non-pinned domains) but is currently
        not used in classification decisions.

        Args:
            domain: The destination hostname or IP address.
            port: The destination port number (reserved for future use).

        Returns:
            True if the domain should be tunneled (pinned), False if
            it should be intercepted (non-pinned).
        """
        domain = domain.lower().rstrip(".")

        # Check 1: Exact domain match
        if domain in self.pinned_list.exact_domains:
            logger.debug("Domain {} matched pinned (exact)", domain)
            return True

        # Check 2: Wildcard pattern match
        if self._matches_wildcard(domain):
            logger.debug("Domain {} matched pinned (wildcard)", domain)
            return True

        # Check 3: IP range match (resolve domain and check IP ranges)
        if self._matches_ip_range(domain):
            logger.debug("Domain {} matched pinned (IP range)", domain)
            return True

        return False

    def _matches_wildcard(self, domain: str) -> bool:
        """Check if the domain matches any wildcard pattern.

        Wildcard patterns like "*.telegram.org" should match
        "api.telegram.org" and "web.telegram.org" but NOT
        "telegram.org.evil.com". The pattern also matches the
        base domain itself (e.g., "*.telegram.org" matches "telegram.org").

        Args:
            domain: The domain to check against all wildcard patterns.

        Returns:
            True if any wildcard pattern matches, False otherwise.
        """
        for pattern in self.pinned_list.wildcard_patterns:
            # Extract the base domain from the wildcard pattern
            # *.telegram.org → telegram.org
            base = pattern.lstrip("*.")

            # The domain either equals the base or ends with .base
            if domain == base or domain.endswith("." + base):
                return True

        return False

    def _matches_ip_range(self, domain: str) -> bool:
        """Check if the domain resolves to a pinned IP range.

        Some services (like Telegram) operate from well-known IP blocks.
        Even if a client connects by IP address rather than domain,
        we can still detect and tunnel these connections.

        DNS resolution is only performed if IP ranges are configured,
        and results are not cached to avoid stale entries.

        Args:
            domain: The domain or IP address to check.

        Returns:
            True if the domain resolves to a pinned IP range, False otherwise.
        """
        if not self.pinned_list.ip_ranges:
            return False

        # If domain is already an IP, check directly
        ip_address = self._try_parse_ip(domain)
        if ip_address is None:
            # Resolve domain to IP
            ip_address = resolve_domain(domain)

        if ip_address and ip_in_range(ip_address, list(self.pinned_list.ip_ranges)):
            return True

        return False

    @staticmethod
    def _try_parse_ip(value: str) -> Optional[str]:
        """Try to parse a string as an IPv4 or IPv6 address.

        Returns the string itself if it's a valid IP, None otherwise.
        Uses a simple heuristic: if the string contains only digits,
        dots, and colons, attempt to parse it.

        Args:
            value: String that might be an IP address.

        Returns:
            The IP address string if valid, None otherwise.
        """
        import ipaddress

        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            return None

    def get_classification_info(self, domain: str) -> dict:
        """Get detailed classification information for a domain.

        Useful for debugging and logging to understand why a domain
        was classified as pinned or non-pinned.

        Args:
            domain: The domain to analyze.

        Returns:
            A dictionary with classification details including
            match type and matched pattern (if any).
        """
        domain = domain.lower().rstrip(".")

        if domain in self.pinned_list.exact_domains:
            return {
                "domain": domain,
                "pinned": True,
                "match_type": "exact",
                "matched_pattern": domain,
            }

        for pattern in self.pinned_list.wildcard_patterns:
            base = pattern.lstrip("*.")
            if domain == base or domain.endswith("." + base):
                return {
                    "domain": domain,
                    "pinned": True,
                    "match_type": "wildcard",
                    "matched_pattern": pattern,
                }

        ip_address = self._try_parse_ip(domain) or resolve_domain(domain)
        if ip_address and ip_in_range(ip_address, list(self.pinned_list.ip_ranges)):
            return {
                "domain": domain,
                "pinned": True,
                "match_type": "ip_range",
                "resolved_ip": ip_address,
            }

        return {
            "domain": domain,
            "pinned": False,
            "match_type": None,
            "matched_pattern": None,
        }
