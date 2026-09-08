"""AdGuard Rules Merger v3 — async, streaming, incremental.

V3 highlights (Phase 1 complete):
  - aiohttp + asyncio for true concurrent I/O (up to 100 connections)
  - Streaming parser (generator-based) for memory-efficient processing
  - Incremental cache with HTTP ETag / Last-Modified / content hash
  - 4-phase dedup: normalized → exact → wildcard → allow-override
  - V2-compatible sync API via RuleEngine alias
  - Rule categories and quality scoring infrastructure (Phase 2 ready)
"""

from .cache import SourceCache, CacheEntry
from .core import (
    AsyncRuleEngine,
    RuleEngine,        # V2-compatible alias
    DomainTrie,
    DedupReport,
    FetchResult,
)
from .models import (
    Rule,
    SourceMeta,
    MergeStats,
    CATEGORY_ADS,
    CATEGORY_MALWARE,
    CATEGORY_TRACKING,
    CATEGORY_PHISHING,
    CATEGORY_MINING,
    CATEGORY_OTHER,
    CATEGORY_COMMENT,
    ALL_CATEGORIES,
)
from .normalizer import RuleNormalizer
from .parser import RuleParser
from .reporter import MergeReporter

__version__ = "3.0.0"
__all__ = [
    # core
    "AsyncRuleEngine", "RuleEngine", "DomainTrie", "DedupReport", "FetchResult",
    # models
    "Rule", "SourceMeta", "MergeStats",
    "CATEGORY_ADS", "CATEGORY_MALWARE", "CATEGORY_TRACKING",
    "CATEGORY_PHISHING", "CATEGORY_MINING", "CATEGORY_OTHER",
    "CATEGORY_COMMENT", "ALL_CATEGORIES",
    # components
    "RuleParser", "RuleNormalizer", "SourceCache", "CacheEntry",
    "MergeReporter",
]
