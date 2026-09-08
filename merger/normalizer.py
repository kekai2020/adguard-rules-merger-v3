"""V3 Rule normalizer — fuzzy dedup and semantic equivalence detection.

Implements the normalization layer described in Phase 1 / Phase 2:
  - Canonical domain normalization (www stripping, trailing dot, case)
  - Format equivalence (hosts format ↔ AdGuard format)
  - www-prefix equivalence under configurable conditions
  - Normalized key generation for hash-based fuzzy dedup

This module is intentionally pure (no I/O) so it can be used both in
the streaming dedup pipeline and as a standalone utility.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .models import Rule


# ── compiled patterns ────────────────────────────────────────────

_RE_WWW_PREFIX = re.compile(r"^www\.")
_RE_TRAILING_DOT = re.compile(r"\.$")
_RE_MULTI_DOT = re.compile(r"\.{2,}")


class RuleNormalizer:
    """Normalizes rules to a canonical form for fuzzy deduplication.

    Configuration:
        strip_www:    Treat www.example.com and example.com as equivalent.
                      Default False (conservative — www is a real subdomain).
        lowercase:    Always lowercase domains (default True).
        strip_trailing_dot: Remove trailing FQDN dot (default True).
    """

    def __init__(
        self,
        strip_www: bool = False,
        lowercase: bool = True,
        strip_trailing_dot: bool = True,
    ) -> None:
        self.strip_www = strip_www
        self.lowercase = lowercase
        self.strip_trailing_dot = strip_trailing_dot

    # ── domain normalization ────────────────────────────────────

    def normalize_domain(self, domain: str) -> str:
        """Return the canonical form of a domain string."""
        d = domain.strip()
        if self.lowercase:
            d = d.lower()
        # strip wildcard prefix temporarily
        is_wild = d.startswith("*.")
        if is_wild:
            d = d[2:]
        if self.strip_trailing_dot:
            d = _RE_TRAILING_DOT.sub("", d)
        if self.strip_www:
            d = _RE_WWW_PREFIX.sub("", d)
        # collapse accidental multi-dots
        d = _RE_MULTI_DOT.sub(".", d)
        if is_wild:
            d = "*." + d
        return d

    # ── rule normalization key ──────────────────────────────────

    def normalized_key(self, rule: Rule) -> Tuple[str, str, bool]:
        """Generate a fuzzy-dedup key for a rule.

        Returns (normalized_domain, rule_type, wildcard) where
        normalized_domain has all configured normalizations applied.

        Two rules with the same key are considered semantically equivalent
        and can be merged (sources unioned).
        """
        norm = self.normalize_domain(rule.domain)
        # strip wildcard for the key domain portion (wildcard flag carries it)
        if norm.startswith("*."):
            norm = norm[2:]
        return (norm, rule.rule_type, rule.wildcard)

    # ── format equivalence helpers ───────────────────────────────

    @staticmethod
    def hosts_to_adguard(domain: str) -> str:
        """Convert a hosts-file domain to canonical AdGuard block format."""
        return f"||{domain}^"

    @staticmethod
    def is_hosts_format(line: str) -> bool:
        """Check if a line looks like a hosts file entry."""
        return bool(re.match(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+\S+", line.strip()))

    # ── www-equivalence check ───────────────────────────────────

    def are_equivalent(self, rule_a: Rule, rule_b: Rule) -> bool:
        """Check if two rules are semantically equivalent under config."""
        if rule_a.rule_type != rule_b.rule_type:
            return False
        if rule_a.wildcard != rule_b.wildcard:
            return False
        return self.normalize_domain(rule_a.domain) == self.normalize_domain(rule_b.domain)


# ── module-level convenience ──────────────────────────────────────

_default_normalizer = RuleNormalizer()


def normalize_domain(domain: str) -> str:
    """Convenience: normalize a domain with default settings."""
    return _default_normalizer.normalize_domain(domain)


def normalized_key(rule: Rule) -> Tuple[str, str, bool]:
    """Convenience: get a normalized dedup key with default settings."""
    return _default_normalizer.normalized_key(rule)
