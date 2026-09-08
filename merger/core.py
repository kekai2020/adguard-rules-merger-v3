"""V3 Core engine — async IO, streaming dedup, ETag cache."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp

from .cache import SourceCache
from .models import Rule
from .parser import RuleParser

logger = logging.getLogger(__name__)


# ── Domain Trie ────────────────────────────────────────────────


class DomainTrie:
    """Trie for wildcard coverage detection. TLD-first ordering."""

    __slots__ = ('root',)

    def __init__(self) -> None:
        self.root: Dict[str, Any] = {}

    def add(self, domain: str) -> None:
        node = self.root
        for part in reversed(domain.lower().split('.')):
            node = node.setdefault(part, {})
        node['__wc__'] = True

    def is_covered(self, domain: str) -> bool:
        node = self.root
        for part in reversed(domain.lower().split('.')):
            if '__wc__' in node:
                return True
            if part not in node:
                return False
            node = node[part]
        return False


# ── Dedup Report ───────────────────────────────────────────────


class DedupReport:
    __slots__ = ('exact_merged', 'wildcard_removed', 'conflict_resolved')

    def __init__(self) -> None:
        self.exact_merged = 0
        self.wildcard_removed = 0
        self.conflict_resolved = 0

    @property
    def total_removed(self) -> int:
        return self.exact_merged + self.wildcard_removed + self.conflict_resolved

    def summary(self) -> str:
        return (f'exact={self.exact_merged} wildcard={self.wildcard_removed} '
                f'conflict={self.conflict_resolved} total={self.total_removed}')


# ── Fetch Result ───────────────────────────────────────────────


class FetchResult:
    """Result of fetching a single source."""
    __slots__ = ('url', 'content', 'from_cache', 'status', 'error')

    def __init__(self, url: str, content: str = '', from_cache: bool = False,
                 status: int = 0, error: str = '') -> None:
        self.url = url
        self.content = content
        self.from_cache = from_cache
        self.status = status
        self.error = error


# ── Rule Engine ────────────────────────────────────────────────


class RuleEngine:
    """Async-first engine with sync compatibility wrapper."""

    def __init__(
        self,
        timeout: int = 60,
        max_workers: int = 20,
        allow_overrides_block: bool = True,
        cache_dir: str = '.cache/sources',
        cache_ttl: int = 3600,
        use_cache: bool = True,
    ) -> None:
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_workers = max_workers
        self.allow_overrides_block = allow_overrides_block
        self.parser = RuleParser()
        self.cache = SourceCache(cache_dir, cache_ttl) if use_cache else None
        self.semaphore = asyncio.Semaphore(max_workers)

    # ── async fetch ────────────────────────────────────────────

    async def _fetch_one(
        self, session: aiohttp.ClientSession, url: str,
        progress_cb=None,
    ) -> FetchResult:
        """Fetch a single source with cache support."""
        # Check cache first
        if self.cache:
            cached = self.cache.read(url)
            if cached is not None:
                logger.debug('Cache hit: %s', url)
                if progress_cb:
                    progress_cb(url, True)
                return FetchResult(url, content=cached, from_cache=True, status=200)

        # Fetch from network
        headers = self.cache.get_headers(url) if self.cache else {}
        async with self.semaphore:
            try:
                async with session.get(url, headers=headers, timeout=self.timeout) as resp:
                    if resp.status == 304 and self.cache:
                        # Not modified — update timestamp
                        self.cache.update_headers(
                            url,
                            etag=resp.headers.get('ETag', ''),
                            last_modified=resp.headers.get('Last-Modified', ''),
                        )
                        cached = self.cache.read(url)
                        if cached:
                            if progress_cb:
                                progress_cb(url, True)
                            return FetchResult(url, content=cached, from_cache=True, status=304)

                    resp.raise_for_status()
                    content = await resp.text()

                    # Update cache
                    if self.cache:
                        self.cache.write(
                            url, content,
                            etag=resp.headers.get('ETag', ''),
                            last_modified=resp.headers.get('Last-Modified', ''),
                        )

                    if progress_cb:
                        progress_cb(url, False)
                    return FetchResult(url, content=content, status=resp.status)

            except Exception as exc:
                logger.warning('Failed %s: %s', url, exc)
                if progress_cb:
                    progress_cb(url, False)
                return FetchResult(url, error=str(exc))

    async def fetch_all(
        self, urls: List[str], progress_cb=None,
    ) -> List[FetchResult]:
        """Fetch all sources concurrently."""
        connector = aiohttp.TCPConnector(limit=self.max_workers, force_close=True)
        async with aiohttp.ClientSession(
            connector=connector,
            headers={'User-Agent': 'AdGuard-Rules-Merger/3.0'},
        ) as session:
            tasks = [self._fetch_one(session, url, progress_cb) for url in urls]
            return await asyncio.gather(*tasks)

    # ── streaming dedup ────────────────────────────────────────

    def deduplicate(self, rules_iter) -> Tuple[List[Rule], DedupReport]:
        """3-phase dedup from an iterator (streaming-friendly).

        Phase 1: Exact dedup with source merging
        Phase 2: Wildcard coverage
        Phase 3: Allow-overrides-block
        """
        report = DedupReport()

        # Phase 1: accumulate into dicts by type
        block_map: Dict[Tuple[str, bool], Rule] = {}
        allow_map: Dict[Tuple[str, bool], Rule] = {}
        comments: Dict[str, Rule] = {}

        for r in rules_iter:
            if r.rule_type == 'block':
                key = (r._norm, r.wildcard)
                existing = block_map.get(key)
                if existing is None:
                    block_map[key] = r
                else:
                    existing.sources |= r.sources
                    report.exact_merged += 1
            elif r.rule_type == 'allow':
                key = (r._norm, r.wildcard)
                existing = allow_map.get(key)
                if existing is None:
                    allow_map[key] = r
                else:
                    existing.sources |= r.sources
                    report.exact_merged += 1
            else:
                if r.raw not in comments:
                    comments[r.raw] = r
                else:
                    report.exact_merged += 1

        # Phase 2: wildcard coverage
        block_wild: Set[str] = {k[0] for k in block_map if k[1]}
        allow_wild: Set[str] = {k[0] for k in allow_map if k[1]}

        if block_wild:
            trie = DomainTrie()
            for d in block_wild:
                trie.add(d)
            to_remove = [k for k in block_map
                         if not k[1] and trie.is_covered(k[0])]
            for k in to_remove:
                del block_map[k]
                report.wildcard_removed += 1

        if allow_wild:
            trie = DomainTrie()
            for d in allow_wild:
                trie.add(d)
            to_remove = [k for k in allow_map
                         if not k[1] and trie.is_covered(k[0])]
            for k in to_remove:
                del allow_map[k]
                report.wildcard_removed += 1

        # Phase 3: allow-overrides-block
        if self.allow_overrides_block:
            block_norms = {k[0] for k in block_map}
            allow_norms = {k[0] for k in allow_map}
            conflict_norms = block_norms & allow_norms
            if conflict_norms:
                for norm in conflict_norms:
                    allow_rules = [v for k, v in allow_map.items() if k[0] == norm]
                    block_rules = [v for k, v in block_map.items() if k[0] == norm]
                    for ar in allow_rules:
                        for br in block_rules:
                            ar.sources |= br.sources
                    to_remove = [k for k in block_map if k[0] == norm]
                    for k in to_remove:
                        del block_map[k]
                        report.conflict_resolved += 1

        result = list(block_map.values()) + list(allow_map.values()) + list(comments.values())
        return result, report

    # ── async merge ────────────────────────────────────────────

    async def async_merge(
        self,
        sources: List[str],
        *,
        return_stats: bool = False,
        detect_conflicts: bool = False,
        progress_cb=None,
    ) -> Any:
        """Full async merge pipeline."""
        logger.info('Merging %d sources', len(sources))
        t0 = time.time()

        # Fetch all
        results = await self.fetch_all(sources, progress_cb)
        ok_count = sum(1 for r in results if r.content and not r.error)
        cache_hits = sum(1 for r in results if r.from_cache)
        logger.info('Fetched %d/%d sources (%d cache hits)', ok_count, len(sources), cache_hits)

        # Stream parse + dedup
        def all_rules():
            for r in results:
                if r.content and not r.error:
                    yield from self.parser.parse_iter(r.content, source=r.url)

        deduped, report = self.deduplicate(all_rules())

        block_n = sum(1 for r in deduped if r.rule_type == 'block')
        allow_n = sum(1 for r in deduped if r.rule_type == 'allow')
        comment_n = sum(1 for r in deduped if r.rule_type == 'comment')
        total_before = report.exact_merged + report.wildcard_removed + report.conflict_resolved + len(deduped)
        elapsed = time.time() - t0
        dedup_rate = (1 - len(deduped) / total_before) * 100 if total_before else 0

        logger.info('Deduped %d → %d (%.1f%%) in %.2fs', total_before, len(deduped), dedup_rate, elapsed)
        logger.info('Dedup: %s', report.summary())

        if not return_stats and not detect_conflicts:
            return deduped

        stats: Dict[str, Any] = {
            'total_before': total_before,
            'total_after': len(deduped),
            'dedup_rate': dedup_rate,
            'block_count': block_n,
            'allow_count': allow_n,
            'comment_count': comment_n,
            'elapsed_time': elapsed,
            'sources_ok': ok_count,
            'sources_total': len(sources),
            'cache_hits': cache_hits,
            'exact_merged': report.exact_merged,
            'wildcard_removed': report.wildcard_removed,
            'conflict_resolved': report.conflict_resolved,
        }

        result: Dict[str, Any] = {'rules': deduped, 'stats': stats}
        if detect_conflicts:
            result['conflicts'] = self._detect_conflicts(deduped)
            stats['conflict_count'] = len(result['conflicts'])

        return result

    # ── sync wrapper ───────────────────────────────────────────

    def merge(self, sources: List[str], **kwargs) -> Any:
        """Sync wrapper around async_merge."""
        return asyncio.run(self.async_merge(sources, **kwargs))

    # ── conflict detection ─────────────────────────────────────

    @staticmethod
    def _detect_conflicts(rules: List[Rule]) -> List[Dict[str, Any]]:
        block_map: Dict[str, List[Rule]] = defaultdict(list)
        allow_map: Dict[str, List[Rule]] = defaultdict(list)
        for r in rules:
            if r.rule_type == 'block':
                block_map[r._norm].append(r)
            elif r.rule_type == 'allow':
                allow_map[r._norm].append(r)
        return [
            {'domain': norm, 'block_rules': block_map[norm], 'allow_rules': allow_map[norm]}
            for norm in set(block_map) & set(allow_map)
        ]
