"""
Unit Tests for Domain Classifier.

Tests the pinned domain matching logic including exact matches,
wildcard patterns, IP ranges, and the full classification pipeline.
"""

import pytest
import os
import tempfile
import yaml

from localbridge.classifier.pinned_list import PinnedList, PinnedListLoader
from localbridge.classifier.domain import DomainClassifier
from localbridge.config import Config


# ---------------------------------------------------------------------------
# PinnedList Tests
# ---------------------------------------------------------------------------


class TestPinnedList:
    """Tests for the PinnedList data structure."""

    def test_add_exact_domain(self):
        """Exact domain entries should be stored in exact_domains set."""
        pinned = PinnedList()
        pinned.add_entry("github.com")
        assert "github.com" in pinned.exact_domains
        assert len(pinned.wildcard_patterns) == 0
        assert len(pinned.ip_ranges) == 0

    def test_add_wildcard_pattern(self):
        """Wildcard entries (starting with *.) should go to wildcard_patterns."""
        pinned = PinnedList()
        pinned.add_entry("*.telegram.org")
        assert "*.telegram.org" in pinned.wildcard_patterns
        assert len(pinned.exact_domains) == 0

    def test_add_ip_range(self):
        """CIDR notation entries should go to ip_ranges."""
        pinned = PinnedList()
        pinned.add_entry("149.154.167.0/24")
        assert "149.154.167.0/24" in pinned.ip_ranges

    def test_ignore_comments(self):
        """Lines starting with # should be ignored."""
        pinned = PinnedList()
        pinned.add_entry("# this is a comment")
        assert pinned.total_entries == 0

    def test_ignore_empty_strings(self):
        """Empty strings should be ignored."""
        pinned = PinnedList()
        pinned.add_entry("")
        pinned.add_entry("   ")
        assert pinned.total_entries == 0

    def test_case_insensitive(self):
        """Domain entries should be normalized to lowercase."""
        pinned = PinnedList()
        pinned.add_entry("GitHub.COM")
        assert "github.com" in pinned.exact_domains

    def test_total_entries(self):
        """total_entries should count all categories."""
        pinned = PinnedList()
        pinned.add_entry("github.com")
        pinned.add_entry("*.telegram.org")
        pinned.add_entry("149.154.167.0/24")
        assert pinned.total_entries == 3


# ---------------------------------------------------------------------------
# PinnedListLoader Tests
# ---------------------------------------------------------------------------


class TestPinnedListLoader:
    """Tests for loading pinned lists from YAML and text files."""

    def _create_yaml_file(self, entries: list) -> str:
        """Create a temporary YAML config file with given entries."""
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            yaml.dump({"pinned_domains": entries}, f)
        return path

    def _create_text_file(self, lines: list) -> str:
        """Create a temporary text file with given lines."""
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines))
        return path

    def test_load_yaml(self):
        """Should correctly load entries from a YAML file."""
        yaml_path = self._create_yaml_file(["*.telegram.org", "github.com"])
        loader = PinnedListLoader(yaml_path, "/nonexistent/override.txt")
        pinned = loader.load()
        assert "*.telegram.org" in pinned.wildcard_patterns
        assert "github.com" in pinned.exact_domains
        os.unlink(yaml_path)

    def test_load_user_overrides(self):
        """Should correctly merge entries from user override file."""
        yaml_path = self._create_yaml_file(["*.telegram.org"])
        user_path = self._create_text_file(["*.mybank.com", "# comment", "private.com"])
        loader = PinnedListLoader(yaml_path, user_path)
        pinned = loader.load()
        assert "*.telegram.org" in pinned.wildcard_patterns
        assert "*.mybank.com" in pinned.wildcard_patterns
        assert "private.com" in pinned.exact_domains
        os.unlink(yaml_path)
        os.unlink(user_path)

    def test_missing_yaml_file(self):
        """Should handle missing YAML file gracefully."""
        loader = PinnedListLoader("/nonexistent/config.yaml", "/nonexistent/override.txt")
        pinned = loader.load()
        assert pinned.total_entries == 0

    def test_empty_yaml(self):
        """Should handle empty YAML file gracefully."""
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            f.write("")
        loader = PinnedListLoader(path, "/nonexistent/override.txt")
        pinned = loader.load()
        assert pinned.total_entries == 0
        os.unlink(path)


# ---------------------------------------------------------------------------
# DomainClassifier Tests
# ---------------------------------------------------------------------------


class TestDomainClassifier:
    """Tests for the domain classification engine."""

    def _make_classifier(self, entries: list, user_entries: list = None) -> DomainClassifier:
        """Create a DomainClassifier with temporary config files."""
        yaml_path = tempfile.mkstemp(suffix=".yaml")[1]
        with open(yaml_path, "w") as f:
            yaml.dump({"pinned_domains": entries}, f)

        user_path = "/nonexistent/override.txt"
        if user_entries:
            fd, user_path = tempfile.mkstemp(suffix=".txt")
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(user_entries))

        config = Config()
        config.pinned_domains.config_file = yaml_path
        config.pinned_domains.user_override_file = user_path

        classifier = DomainClassifier(config)
        os.unlink(yaml_path)
        if user_entries:
            os.unlink(user_path)

        return classifier

    def test_exact_match(self):
        """Exact domain matches should be classified as pinned."""
        classifier = self._make_classifier(["github.com"])
        assert classifier.is_pinned("github.com") is True

    def test_exact_match_case_insensitive(self):
        """Classification should be case-insensitive."""
        classifier = self._make_classifier(["github.com"])
        assert classifier.is_pinned("GitHub.COM") is True

    def test_wildcard_match(self):
        """Wildcard patterns should match subdomains."""
        classifier = self._make_classifier(["*.telegram.org"])
        assert classifier.is_pinned("api.telegram.org") is True
        assert classifier.is_pinned("web.telegram.org") is True

    def test_wildcard_matches_base_domain(self):
        """Wildcard patterns should also match the base domain itself."""
        classifier = self._make_classifier(["*.telegram.org"])
        assert classifier.is_pinned("telegram.org") is True

    def test_wildcard_no_false_match(self):
        """Wildcard patterns should NOT match unrelated domains."""
        classifier = self._make_classifier(["*.telegram.org"])
        assert classifier.is_pinned("telegram.org.evil.com") is False

    def test_non_pinned_domain(self):
        """Unknown domains should be classified as non-pinned."""
        classifier = self._make_classifier(["*.telegram.org"])
        assert classifier.is_pinned("example.com") is False

    def test_user_override(self):
        """User override entries should be included in classification."""
        classifier = self._make_classifier(
            ["*.telegram.org"],
            user_entries=["*.mybank.com"],
        )
        assert classifier.is_pinned("api.mybank.com") is True

    def test_classification_info_pinned(self):
        """get_classification_info should return detailed match info for pinned domains."""
        classifier = self._make_classifier(["*.telegram.org"])
        info = classifier.get_classification_info("api.telegram.org")
        assert info["pinned"] is True
        assert info["match_type"] == "wildcard"
        assert info["matched_pattern"] == "*.telegram.org"

    def test_classification_info_non_pinned(self):
        """get_classification_info should return non-pinned for unknown domains."""
        classifier = self._make_classifier(["*.telegram.org"])
        info = classifier.get_classification_info("example.com")
        assert info["pinned"] is False
        assert info["match_type"] is None
