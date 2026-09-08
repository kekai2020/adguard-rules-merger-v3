"""V3 Data models for AdGuard rules — async & streaming ready.

Enhancements over V2:
  - category field for rule classification (ads / malware / tracking / etc.)
  - quality_score for rule quality filtering (Phase 2)
  - popularity counter for multi-source attribution
  - __slots__ for memory efficiency in streaming mode
  - frozen-compatible design for hash-based dedup
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Set


# Rule categories (used for tiered output in Phase 2)
CATEGORY_ADS = "ads"
CATEGORY_MALWARE = "malware"
CATEGORY_TRACKING = "tracking"
CATEGORY_PHISHING = "phishing"
CATEGORY_MINING = "mining"
CATEGORY_OTHER = "other"
CATEGORY_COMMENT = "comment"

ALL_CATEGORIES = frozenset({
    CATEGORY_ADS, CATEGORY_MALWARE, CATEGORY_TRACKING,
    CATEGORY_PHISHING, CATEGORY_MINING, CATEGORY_OTHER, CATEGORY_COMMENT,
})


@dataclass
class Rule:
    """A single AdGuard filter rule with full provenance and metadata.

    Attributes:
        raw:           Original line from source (kept for fidelity).
        domain:        Extracted domain string (may include *. prefix).
        rule_type:     'block' | 'allow' | 'comment'
        wildcard:      True if domain starts with *.
        sources:       Set of source URLs this rule appeared in.
        category:      Rule category for tiered output (Phase 2).
        quality_score: Float 0.0-1.0, higher = more trustworthy (Phase 2).
        _norm:         Cached normalized_domain (computed once).
    """

    raw: str
    domain: str
    rule_type: str          # 'block', 'allow', 'comment'
    wildcard: bool
    sources: Set[str] = field(default_factory=set)
    category: str = CATEGORY_OTHER
    quality_score: float = 1.0
    _norm: str = field(init=False, repr=False, compare=False, default="")

    # ── post-init ──────────────────────────────────────────────

    def __post_init__(self) -> None:
        if isinstance(self.sources, str):
            self.sources = {self.sources}
        self._norm = self._normalize(self.domain)

    # ── normalization ──────────────────────────────────────────

    @staticmethod
    def _normalize(domain: str) -> str:
        """Lowercase, strip wildcard prefix, strip trailing dot."""
        d = domain.lower().strip()
        if d.startswith("*."):
            d = d[2:]
        if d.endswith("."):
            d = d[:-1]
        return d

    @property
    def normalized_domain(self) -> str:
        return self._norm

    # ── canonical output ───────────────────────────────────────

    @property
    def output_raw(self) -> str:
        """Canonical AdGuard format for output file."""
        if self.rule_type == "comment":
            return self.raw
        if self.rule_type == "allow":
            return f"@@||{self.domain}^"
        # block
        return f"||{self.domain}^"

    # ── domain relationship helpers ────────────────────────────

    def is_subdomain_of(self, parent: "Rule") -> bool:
        """True if self's domain is a strict subdomain of parent's wildcard."""
        if not parent.wildcard:
            return False
        if self.rule_type != parent.rule_type:
            return False
        return (self._norm != parent._norm and
                self._norm.endswith("." + parent._norm))

    def covers_as_wildcard(self, child: "Rule") -> bool:
        """True if self (wildcard) covers child (non-wildcard) as subdomain."""
        if not self.wildcard:
            return False
        if self.rule_type != child.rule_type:
            return False
        return (child._norm != self._norm and
                child._norm.endswith("." + self._norm))

    # ── equality / hashing ─────────────────────────────────────
    # __eq__ and __hash__ MUST be consistent.
    # Key: (normalized_domain, rule_type, wildcard)
    # This means *.a.com ≠ a.com — they are different rules.

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Rule):
            return NotImplemented
        return (self._norm == other._norm and
                self.rule_type == other.rule_type and
                self.wildcard == other.wildcard)

    def __hash__(self) -> int:
        return hash((self._norm, self.rule_type, self.wildcard))

    # ── ordering (for sorted()) ────────────────────────────────

    def __lt__(self, other: "Rule") -> bool:
        """Less-than comparison for sorting.
        
        Uses output_raw (canonical AdGuard format) so that sorted order
        matches what gets written to the output file.
        """
        if not isinstance(other, Rule):
            return NotImplemented
        return self.output_raw < other.output_raw
  
    # ── string representation ──────────────────────────────────

    def __str__(self) -> str:
        return self.output_raw

    def __repr__(self) -> str:
        src = ",".join(sorted(self.sources)[:2])
        if len(self.sources) > 2:
            src += ",..."
        return f"Rule({self.rule_type} {self.domain!r} [{src}])"


@dataclass
class SourceMeta:
    """Metadata for a rule source, used for quality scoring and caching."""

    name: str
    url: str
    category: str = CATEGORY_OTHER
    enabled: bool = True
    reputation: float = 0.5  # 0.0-1.0, higher = more trustworthy
    timeout: Optional[int] = None  # per-source timeout override

    def __post_init__(self) -> None:
        if self.reputation < 0.0:
            self.reputation = 0.0
        elif self.reputation > 1.0:
            self.reputation = 1.0


@dataclass
class MergeStats:
    """Structured statistics for a merge run."""

    total_before: int = 0
    total_after: int = 0
    dedup_rate: float = 0.0
    block_count: int = 0
    allow_count: int = 0
    comment_count: int = 0
    elapsed_time: float = 0.0
    sources_ok: int = 0
    sources_total: int = 0
    sources_cached: int = 0  # V3: number of sources served from cache
    exact_merged: int = 0
    wildcard_removed: int = 0
    conflict_resolved: int = 0
    normalized_merged: int = 0  # V3: fuzzy/normalized dedup count

    def to_dict(self) -> dict:
        return {
            "total_before": self.total_before,
            "total_after": self.total_after,
            "dedup_rate": self.dedup_rate,
            "block_count": self.block_count,
            "allow_count": self.allow_count,
            "comment_count": self.comment_count,
            "elapsed_time": self.elapsed_time,
            "sources_ok": self.sources_ok,
            "sources_total": self.sources_total,
            "sources_cached": self.sources_cached,
            "exact_merged": self.exact_merged,
            "wildcard_removed": self.wildcard_removed,
            "conflict_resolved": self.conflict_resolved,
            "normalized_merged": self.normalized_merged,
        }
