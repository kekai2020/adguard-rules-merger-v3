"""V3 Async core engine — aiohttp + streaming + incremental cache.

Architecture (Phase 1 complete):
  1. Async fetch: aiohttp.ClientSession with asyncio.gather for true
     concurrent I/O (no GIL contention, 50-100 concurrent connections).
  2. Incremental cache: SourceCache provides ETag / Last-Modified conditional
     requests; 304 responses reuse cached content directly.
  3. Streaming parse: RuleParser.parse_stream() yields Rule objects line-by-
     line; rules are fed into the dedup pipeline as they arrive.
  4. 4-phase dedup:
       Phase 0: Normalized/fuzzy dedup (V3 new — www-equivalence etc.)
       Phase 1: Exact dedup with source merging
       Phase 2: Wildcard coverage (DomainTrie)
       Phase 3: Allow-overrides-block conflict resolution
  5. Sync compatibility: merge_sync() wraps async merge() via asyncio.run().

Dedup key design (unchanged from V2 for correctness):
  Key = (normalized_domain, rule_type, wildcard)
  *.a.com and a.com are NOT the same key — both survive.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple

import aiohttp

from .cache import SourceCache
from .models import Rule, SourceMeta, MergeStats, CATEGORY_OTHER
from .normalizer import RuleNormalizer
from .parser import RuleParser

logger = logging.getLogger(__name__)


# ── Domain Trie ────────────────────────────────────────────────────


class DomainTrie:
    """Trie for wildcard coverage detection.

    Stored with TLD-first ordering:
        *.example.com  →  root['com']['example']['__wc__'] = True

    Coverage rule:
        sub.example.com  →  covered  (parent has wildcard)
        example.com      →  NOT covered  (wildcard = subdomains only)
    """

    __slots__ = ("root",)

    def __init__(self) -> None:
        self.root: Dict[str, Any] = {}

    def add(self, domain: str) -> None:
        """Insert a wildcard domain (without *. prefix)."""
        node = self.root
        for part in reversed(domain.lower().split(".")):
            node = node.setdefault(part, {})
        node["__wc__"] = True

    def is_covered(self, domain: str) -> bool:
        """Check if *domain* is a strict subdomain of any wildcard."""
        node = self.root
        for part in reversed(domain.lower().split(".")):
            if "__wc__" in node:
                return True
            if part not in node:
                return False
            node = node[part]
        return False


# ── Dedup Report ───────────────────────────────────────────────────


class DedupReport:
    """Tracks what was removed and why."""

    __slots__ = (
        "exact_merged",       # sources merged into surviving rule
        "wildcard_removed",   # removed by wildcard coverage
        "conflict_resolved",  # block/allow conflicts resolved
        "normalized_merged",  # V3: fuzzy/normalized dedup
    )

    def __init__(self) -> None:
        self.exact_merged: int = 0
        self.wildcard_removed: int = 0
        self.conflict_resolved: int = 0
        self.normalized_merged: int = 0

    @property
    def total_removed(self) -> int:
        return (
            self.exact_merged
            + self.wildcard_removed
            + self.conflict_resolved
            + self.normalized_merged
        )

    def summary(self) -> str:
        return (
            f"exact_merged={self.exact_merged} "
            f"wildcard_removed={self.wildcard_removed} "
            f"conflict_resolved={self.conflict_resolved} "
            f"normalized_merged={self.normalized_merged} "
            f"total={self.total_removed}"
        )


# ── Fetch result ────────────────────────────────────────────────────


@dataclass
class FetchResult:
    """Result of fetching + parsing one source."""
    url: str
    rules: List[Rule]
    success: bool
    from_cache: bool = False
    error: Optional[str] = None
    elapsed: float = 0.0


# ── Async Rule Engine ───────────────────────────────────────────────


class AsyncRuleEngine:
    """Fetch, parse, deduplicate, and merge AdGuard filter rules (async).

    This is the V3 core engine.  Use ``merge()`` for async usage or
    ``merge_sync()`` for a drop-in synchronous replacement of V2's
    ``RuleEngine.merge()``.

    Args:
        timeout:             Per-request timeout in seconds.
        max_concurrency:     Max concurrent aiohttp requests (default 50).
        allow_overrides_block: Enable Phase 3 allow-wins conflict resolution.
        cache_dir:           Directory for incremental cache (None = disable).
        cache_ttl:           Cache TTL in seconds (0 = no time-based expiry).
        cache_max_size_mb:   Max cache size in MB (0 = unlimited).
        enable_normalized_dedup: Enable Phase 0 fuzzy/normalized dedup.
        normalizer:          Custom RuleNormalizer (default = conservative).
    """

    def __init__(
        self,
        timeout: int = 60,
        max_concurrency: int = 50,
        allow_overrides_block: bool = True,
        cache_dir: Optional[str] = None,
        cache_ttl: int = 0,
        cache_max_size_mb: int = 0,
        enable_normalized_dedup: bool = False,
        normalizer: Optional[RuleNormalizer] = None,
    ) -> None:
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.allow_overrides_block = allow_overrides_block
        self.enable_normalized_dedup = enable_normalized_dedup
        self.normalizer = normalizer or RuleNormalizer()
        self.parser = RuleParser()

        # cache
        self.cache: Optional[SourceCache] = None
        if cache_dir is not None:
            self.cache = SourceCache(
                cache_dir=cache_dir,
                ttl_seconds=cache_ttl,
                max_size_mb=cache_max_size_mb,
            )
            self.cache.load()

        # aiohttp session (lazily created per merge run)
        self._session: Optional[aiohttp.ClientSession] = None

    # ── context manager ─────────────────────────────────────────

    async def __aenter__(self) -> "AsyncRuleEngine":
        await self._ensure_session()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(limit=self.max_concurrency)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": "AdGuard-Rules-Merger/3.0"},
            )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        if self.cache:
            self.cache.save()

    # ── async fetch ─────────────────────────────────────────────

    async def fetch_source(
        self,
        source: str,
        category: str = CATEGORY_OTHER,
    ) -> Tuple[str, bool]:
        """Fetch one source asynchronously.

        Returns (content_text, from_cache).
        Supports local files and HTTP URLs with incremental caching.
        """
        if not isinstance(source, str) or not source.strip():
            raise ValueError(f"Invalid source: {source!r}")
        source = source.strip()

        # local file
        p = Path(source)
        if p.exists() and p.is_file():
            return p.read_text(encoding="utf-8"), False

        # check cache for conditional headers
        cond_headers: Dict[str, str] = {}
        if self.cache:
            cond_headers = self.cache.conditional_headers(source)

        await self._ensure_session()
        assert self._session is not None

        try:
            async with self._session.get(source, headers=cond_headers) as resp:
                # 304 Not Modified — use cached content
                if resp.status == 304 and self.cache:
                    cached = self.cache.get_content(source)
                    if cached is not None:
                        logger.debug("304 — using cache for %s", source)
                        self.cache.store_not_modified(source)
                        return cached, True
                    # fall through to re-fetch if cache is missing

                resp.raise_for_status()
                text = await resp.text()

                # extract cache headers
                etag = resp.headers.get("ETag")
                last_modified = resp.headers.get("Last-Modified")

                # store in cache
                if self.cache:
                    # check if content actually changed
                    changed = self.cache.content_changed(source, text)
                    self.cache.store(
                        url=source,
                        content=text,
                        etag=etag,
                        last_modified=last_modified,
                    )
                    if not changed:
                        return text, True  # content unchanged, treat as cached

                return text, False

        except aiohttp.ClientError as e:
            # network error — try cache as fallback
            if self.cache:
                cached = self.cache.get_content(source)
                if cached is not None:
                    logger.warning("Network error for %s, using cache: %s", source, e)
                    return cached, True
            raise

    async def fetch_and_parse(
        self,
        source: str,
        category: str = CATEGORY_OTHER,
    ) -> FetchResult:
        """Fetch one source and parse it into a list of Rules."""
        t0 = time.time()
        try:
            text, from_cache = await self.fetch_source(source, category)
            rules = self.parser.parse_text(text, source=source, category=category)

            # update cache rule_count
            if self.cache and not from_cache:
                entry = self.cache.get(source)
                if entry:
                    entry.rule_count = len(rules)

            elapsed = time.time() - t0
            logger.info(
                "Parsed %d rules from %s (%s, %.2fs)",
                len(rules), source,
                "cache" if from_cache else "fetch", elapsed,
            )
            return FetchResult(
                url=source, rules=rules, success=True,
                from_cache=from_cache, elapsed=elapsed,
            )
        except Exception as exc:
            elapsed = time.time() - t0
            logger.warning("Failed %s: %s", source, exc)
            return FetchResult(
                url=source, rules=[], success=False,
                error=str(exc), elapsed=elapsed,
            )

    async def fetch_and_parse_all(
        self,
        sources: List[SourceMeta],
    ) -> Tuple[List[Rule], int, int]:
        """Concurrently fetch + parse all sources.

        Returns (all_rules, success_count, cached_count).
        Uses asyncio.gather with semaphore for concurrency control.
        """
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _bounded(src: SourceMeta) -> FetchResult:
            async with semaphore:
                return await self.fetch_and_parse(src.url, src.category)

        tasks = [_bounded(src) for src in sources]
        results: List[FetchResult] = await asyncio.gather(*tasks)

        all_rules: List[Rule] = []
        ok = 0
        cached = 0
        for r in results:
            if r.success:
                ok += 1
                all_rules.extend(r.rules)
                if r.from_cache:
                    cached += 1
        return all_rules, ok, cached

    # ── streaming fetch (V3 advanced) ───────────────────────────

    async def fetch_stream(
        self,
        source: str,
        category: str = CATEGORY_OTHER,
        chunk_size: int = 8192,
    ) -> AsyncIterator[Rule]:
        """Stream-parse a source: yield Rules as bytes arrive.

        This is the most memory-efficient fetch mode.  It uses aiohttp's
        streaming response body and feeds lines to RuleParser.parse_stream()
        as they become available.

        Note: caching is not applied in stream mode (the response body is
        not fully materialized).  Use fetch_and_parse() for cached sources.
        """
        if not isinstance(source, str) or not source.strip():
            raise ValueError(f"Invalid source: {source!r}")
        source = source.strip()

        # local file — stream line by line
        p = Path(source)
        if p.exists() and p.is_file():
            with open(p, "r", encoding="utf-8") as f:
                for rule in self.parser.parse_stream(f, source, category):
                    yield rule
            return

        await self._ensure_session()
        assert self._session is not None

        async with self._session.get(source) as resp:
            resp.raise_for_status()
            # aiohttp streaming: iterate over lines
            async for line_bytes in resp.content:
                line = line_bytes.decode("utf-8", errors="replace")
                # parse_stream expects an iterator; we feed one line at a time
                for rule in self.parser.parse_stream(iter([line]), source, category):
                    yield rule

    # ── dedup ───────────────────────────────────────────────────

    def deduplicate(
        self, rules: List[Rule]
    ) -> Tuple[List[Rule], DedupReport]:
        """4-phase dedup.  Returns (deduped_rules, report).

        Phase 0: Normalized/fuzzy dedup (V3, optional)
        Phase 1: Exact dedup with source merging
        Phase 2: Wildcard coverage
        Phase 3: Allow-overrides-block (optional)
        """
        report = DedupReport()
        if not rules:
            return [], report

        # Phase 0: normalized dedup
        if self.enable_normalized_dedup:
            rules, rep_norm = self._dedup_normalized(rules)
            report.normalized_merged = rep_norm

        # separate by type
        blocks: List[Rule] = []
        allows: List[Rule] = []
        comments: List[Rule] = []
        for r in rules:
            if r.rule_type == "block":
                blocks.append(r)
            elif r.rule_type == "allow":
                allows.append(r)
            else:
                comments.append(r)

        dedup_blocks, rep_b = self._dedup_type(blocks)
        dedup_allows, rep_a = self._dedup_type(allows)
        dedup_comments, rep_c = self._dedup_comments(comments)

        report.exact_merged += rep_b.exact_merged + rep_a.exact_merged + rep_c.exact_merged
        report.wildcard_removed += rep_b.wildcard_removed + rep_a.wildcard_removed

        merged = dedup_blocks + dedup_allows + dedup_comments

        # Phase 3: allow-overrides-block
        if self.allow_overrides_block:
            merged, rep_conf = self._resolve_conflicts(merged)
            report.conflict_resolved = rep_conf

        return merged, report

    def _dedup_normalized(
        self, rules: List[Rule]
    ) -> Tuple[List[Rule], int]:
        """Phase 0: Fuzzy dedup using normalized domain keys.

        Merges rules that are semantically equivalent under the configured
        normalizer (e.g. www-equivalence if enabled).
        """
        unique: Dict[Tuple[str, str, bool], Rule] = {}
        merged_count = 0

        for r in rules:
            key = self.normalizer.normalized_key(r)
            existing = unique.get(key)
            if existing is None:
                unique[key] = r
            else:
                # merge sources into surviving rule
                existing.sources |= r.sources
                # keep higher quality score
                if r.quality_score > existing.quality_score:
                    existing.quality_score = r.quality_score
                merged_count += 1

        return list(unique.values()), merged_count

    def _dedup_type(
        self, rules: List[Rule]
    ) -> Tuple[List[Rule], DedupReport]:
        """Phase 1 + Phase 2 for a single rule type."""
        report = DedupReport()
        if not rules:
            return [], report

        # Phase 1: exact dedup with source merging
        unique: Dict[Tuple[str, str, bool], Rule] = {}
        wild_domains: Set[str] = set()

        for r in rules:
            key = (r._norm, r.rule_type, r.wildcard)
            existing = unique.get(key)
            if existing is None:
                unique[key] = r
                if r.wildcard:
                    wild_domains.add(r._norm)
            else:
                # merge sources into surviving rule
                existing.sources |= r.sources
                report.exact_merged += 1

        if not wild_domains:
            return list(unique.values()), report

        # Phase 2: wildcard coverage
        trie = DomainTrie()
        for d in wild_domains:
            trie.add(d)

        final: List[Rule] = []
        for r in unique.values():
            if r.wildcard:
                final.append(r)
            elif trie.is_covered(r._norm):
                report.wildcard_removed += 1
            else:
                final.append(r)

        return final, report

    @staticmethod
    def _dedup_comments(
        comments: List[Rule],
    ) -> Tuple[List[Rule], DedupReport]:
        report = DedupReport()
        seen: Set[str] = set()
        out: List[Rule] = []
        for c in comments:
            if c.raw in seen:
                report.exact_merged += 1
                continue
            seen.add(c.raw)
            out.append(c)
        return out, report

    @staticmethod
    def _resolve_conflicts(
        rules: List[Rule],
    ) -> Tuple[List[Rule], int]:
        """Phase 3: if same domain has both block and allow → keep allow."""
        by_key: Dict[Tuple[str, str], List[Rule]] = defaultdict(list)
        for r in rules:
            by_key[(r._norm, r.rule_type)].append(r)

        # find domains with both block and allow
        block_norms = {k[0] for k in by_key if k[1] == "block"}
        allow_norms = {k[0] for k in by_key if k[1] == "allow"}
        conflict_norms = block_norms & allow_norms

        if not conflict_norms:
            return rules, 0

        out: List[Rule] = []
        resolved = 0
        for r in rules:
            if r._norm in conflict_norms:
                if r.rule_type == "allow":
                    # merge block sources into allow rule
                    block_rules = by_key.get((r._norm, "block"), [])
                    for br in block_rules:
                        r.sources |= br.sources
                    out.append(r)
                else:
                    resolved += 1
            else:
                out.append(r)

        return out, resolved

    # ── merge (high-level async) ─────────────────────────────────

    async def merge(
        self,
        sources: List[Any],
        *,
        return_stats: bool = False,
        detect_conflicts: bool = False,
    ) -> Any:
        """Full async merge pipeline.

        Args:
            sources: List of source URLs (str) or SourceMeta objects.
            return_stats: If True, return dict with rules + stats.
            detect_conflicts: If True, include block/allow conflict list.

        Returns:
            List[Rule] if return_stats=False, else dict with
            'rules', 'stats', and optionally 'conflicts'.
        """
        # normalize sources to SourceMeta
        source_metas: List[SourceMeta] = []
        for s in sources:
            if isinstance(s, SourceMeta):
                source_metas.append(s)
            elif isinstance(s, str):
                source_metas.append(SourceMeta(name=s, url=s))
            elif isinstance(s, dict):
                source_metas.append(SourceMeta(
                    name=s.get("name", s.get("url", "unknown")),
                    url=s["url"],
                    category=s.get("category", CATEGORY_OTHER),
                    enabled=s.get("enabled", True),
                    reputation=s.get("reputation", 0.5),
                ))
            else:
                raise TypeError(f"Unsupported source type: {type(s).__name__}")

        # filter enabled
        source_metas = [s for s in source_metas if s.enabled]

        if not source_metas:
            raise ValueError("No enabled sources")

        logger.info("Merging %d sources (async, max_concurrency=%d)",
                     len(source_metas), self.max_concurrency)
        t0 = time.time()

        # fetch + parse (concurrent)
        all_rules, ok, cached = await self.fetch_and_parse_all(source_metas)
        logger.info("Raw rules: %d (from %d/%d sources, %d cached)",
                     len(all_rules), ok, len(source_metas), cached)

        # dedup
        deduped, report = self.deduplicate(all_rules)

        # stats
        block_n = sum(1 for r in deduped if r.rule_type == "block")
        allow_n = sum(1 for r in deduped if r.rule_type == "allow")
        comment_n = sum(1 for r in deduped if r.rule_type == "comment")
        elapsed = time.time() - t0
        dedup_rate = (1 - len(deduped) / len(all_rules)) * 100 if all_rules else 0

        logger.info("Deduped: %d (%.1f%% rate) in %.2fs", len(deduped), dedup_rate, elapsed)
        logger.info("Dedup detail: %s", report.summary())

        stats = MergeStats(
            total_before=len(all_rules),
            total_after=len(deduped),
            dedup_rate=dedup_rate,
            block_count=block_n,
            allow_count=allow_n,
            comment_count=comment_n,
            elapsed_time=elapsed,
            sources_ok=ok,
            sources_total=len(source_metas),
            sources_cached=cached,
            exact_merged=report.exact_merged,
            wildcard_removed=report.wildcard_removed,
            conflict_resolved=report.conflict_resolved,
            normalized_merged=report.normalized_merged,
        )

        if not return_stats and not detect_conflicts:
            return deduped

        result: Dict[str, Any] = {"rules": deduped, "stats": stats.to_dict()}

        if detect_conflicts:
            conflicts = self.detect_conflicts(deduped)
            result["conflicts"] = conflicts
            result["stats"]["conflict_count"] = len(conflicts)

        return result

    # ── sync compatibility layer ─────────────────────────────────

    def merge_sync(
        self,
        sources: List[Any],
        *,
        return_stats: bool = False,
        detect_conflicts: bool = False,
    ) -> Any:
        """Synchronous wrapper for merge() — drop-in V2 replacement.

        Uses asyncio.run() internally.  Do not call from within an
        existing event loop; use await merge() instead.
        """
        async def _run() -> Any:
            async with self:
                # Call the async merge directly (not self.merge, which may
                # be overridden by the V2-compatible RuleEngine alias).
                return await AsyncRuleEngine.merge(
                    self,
                    sources,
                    return_stats=return_stats,
                    detect_conflicts=detect_conflicts,
                )
        return asyncio.run(_run())

    # ── conflict detection ───────────────────────────────────────

    @staticmethod
    def detect_conflicts(rules: List[Rule]) -> List[Dict[str, Any]]:
        """Find domains that have both block and allow rules."""
        block_map: Dict[str, List[Rule]] = defaultdict(list)
        allow_map: Dict[str, List[Rule]] = defaultdict(list)
        for r in rules:
            if r.rule_type == "block":
                block_map[r._norm].append(r)
            elif r.rule_type == "allow":
                allow_map[r._norm].append(r)

        conflicts = []
        for norm in set(block_map) & set(allow_map):
            conflicts.append({
                "domain": norm,
                "block_rules": block_map[norm],
                "allow_rules": allow_map[norm],
            })
        return conflicts


# ── V2-compatible alias ─────────────────────────────────────────────


class RuleEngine(AsyncRuleEngine):
    """V2-compatible alias for AsyncRuleEngine.

    Provides the same constructor signature as V2's RuleEngine and
    a synchronous merge() method for drop-in replacement.
    """

    def __init__(
        self,
        timeout: int = 60,
        max_workers: int = 10,
        allow_overrides_block: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            timeout=timeout,
            max_concurrency=max_workers,
            allow_overrides_block=allow_overrides_block,
            **kwargs,
        )

    def merge(
        self,
        sources: List[Any],
        *,
        return_stats: bool = False,
        detect_conflicts: bool = False,
    ) -> Any:
        """Synchronous merge (V2-compatible)."""
        return self.merge_sync(
            sources,
            return_stats=return_stats,
            detect_conflicts=detect_conflicts,
        )
