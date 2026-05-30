"""
Pinned Domains Database.

Loads and manages the list of domains that must NEVER be intercepted
by the MITM proxy. These domains use certificate pinning, so any
attempt to MITM them would cause connection failures.

The pinned list is populated from two sources:
1. Default YAML configuration (shipped with the application)
2. User override file (optional, for custom pinned domains)

Both sources are merged at load time, with user overrides taking
precedence for any conflicting entries.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set

import yaml
from loguru import logger


@dataclass
class PinnedList:
    """Collection of pinned domain patterns and IP ranges.

    Domains and IP ranges in this list are guaranteed to be tunneled
    transparently without any TLS inspection, ensuring that
    certificate-pinned applications continue to work correctly.

    Attributes:
        exact_domains: Set of exact domain names that are pinned.
        wildcard_patterns: Set of wildcard patterns (e.g., "*.telegram.org").
        ip_ranges: Set of CIDR notation IP ranges that are pinned.
    """

    exact_domains: Set[str] = field(default_factory=set)
    wildcard_patterns: Set[str] = field(default_factory=set)
    ip_ranges: Set[str] = field(default_factory=set)

    def add_entry(self, entry: str) -> None:
        """Add a single entry to the appropriate collection.

        Automatically categorizes the entry based on its format:
        - Wildcard patterns (starting with *.) → wildcard_patterns
        - CIDR notation (containing /) → ip_ranges
        - Everything else → exact_domains

        Args:
            entry: A domain, wildcard pattern, or CIDR range string.
        """
        entry = entry.strip().lower()

        if not entry or entry.startswith("#"):
            return

        if entry.startswith("*."):
            # Wildcard pattern like *.telegram.org
            self.wildcard_patterns.add(entry)
        elif "/" in entry:
            # CIDR range like 149.154.167.0/24
            self.ip_ranges.add(entry)
        else:
            # Exact domain like github.com
            self.exact_domains.add(entry)

    @property
    def total_entries(self) -> int:
        """Return the total number of pinned entries across all categories."""
        return len(self.exact_domains) + len(self.wildcard_patterns) + len(self.ip_ranges)

    def __repr__(self) -> str:
        return (
            f"PinnedList(exact={len(self.exact_domains)}, "
            f"wildcards={len(self.wildcard_patterns)}, "
            f"ip_ranges={len(self.ip_ranges)})"
        )


class PinnedListLoader:
    """Loads and merges pinned domain lists from multiple sources.

    Reads the default YAML configuration file and the optional user
    override file, combining them into a single PinnedList instance.
    The loader handles missing files gracefully and logs warnings
    for malformed entries.

    Attributes:
        config_file: Path to the default YAML pinned domains file.
        user_override_file: Path to the user's custom override file.
    """

    def __init__(self, config_file: str, user_override_file: str):
        """Initialize with paths to the configuration files.

        Args:
            config_file: Path to the default YAML configuration.
            user_override_file: Path to the user override file (tilde-expanded).
        """
        self.config_file = os.path.expanduser(config_file)
        self.user_override_file = os.path.expanduser(user_override_file)

    def load(self) -> PinnedList:
        """Load and merge pinned domain lists from all sources.

        First loads the default YAML file, then overlays any entries
        from the user override file. Returns an empty list if neither
        file exists.

        Returns:
            A PinnedList with entries from all available sources.
        """
        pinned = PinnedList()

        # Load default YAML configuration
        self._load_yaml(pinned)

        # Load user override file
        self._load_user_overrides(pinned)

        logger.info(
            "Loaded pinned domains: {} exact, {} wildcards, {} IP ranges",
            len(pinned.exact_domains),
            len(pinned.wildcard_patterns),
            len(pinned.ip_ranges),
        )

        return pinned

    def _load_yaml(self, pinned: PinnedList) -> None:
        """Load pinned domains from the default YAML configuration.

        Expects a YAML file with a top-level 'pinned_domains' key
        containing a list of domain patterns and IP ranges.

        Args:
            pinned: The PinnedList to populate with entries.
        """
        if not os.path.exists(self.config_file):
            logger.warning("Pinned domains config not found: {}", self.config_file)
            return

        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "pinned_domains" not in data:
                logger.warning("No 'pinned_domains' key in {}", self.config_file)
                return

            entries = data["pinned_domains"]
            if not isinstance(entries, list):
                logger.warning("'pinned_domains' should be a list in {}", self.config_file)
                return

            for entry in entries:
                if isinstance(entry, str):
                    pinned.add_entry(entry)

            logger.debug("Loaded {} entries from YAML config", len(entries))

        except yaml.YAMLError as e:
            logger.error("Failed to parse YAML config: {}", e)
        except OSError as e:
            logger.error("Failed to read YAML config: {}", e)

    def _load_user_overrides(self, pinned: PinnedList) -> None:
        """Load pinned domains from the user override file.

        The user override file is a simple text file with one domain
        per line. Lines starting with # are treated as comments.
        This file is optional — if it doesn't exist, no error is raised.

        Args:
            pinned: The PinnedList to populate with user entries.
        """
        if not os.path.exists(self.user_override_file):
            logger.debug("No user override file at {}", self.user_override_file)
            return

        count = 0
        try:
            with open(self.user_override_file, "r", encoding="utf-8") as f:
                for line in f:
                    entry = line.strip()
                    if entry and not entry.startswith("#"):
                        pinned.add_entry(entry)
                        count += 1

            logger.debug("Loaded {} entries from user override file", count)

        except OSError as e:
            logger.error("Failed to read user override file: {}", e)
