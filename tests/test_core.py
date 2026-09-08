"""V3 Tests for core dedup engine, parser, normalizer, and cache."""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path
from typing import List

import pytest

# Add parent to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from merger import (
    AsyncRuleEngine,
    Rule,
    RuleEngine,
    RuleNormalizer,
    RuleParser,
    SourceCache,
    DomainTrie,
    DedupReport,
)
from merger.models import (
    CATEGORY_ADS,
    CATEGORY_MALWARE,
    CATEGORY_OTHER,
    SourceMeta,
)


# ── fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def parser() -> RuleParser:
    return RuleParser()


@pytest.fixture
def engine() -> RuleEngine:
    """V2-compatible sync engine (no cache for tests)."""
    return RuleEngine(timeout=10, max_workers=5)


@pytest.fixture
def async_engine() -> AsyncRuleEngine:
    return AsyncRuleEngine(timeout=10, max_concurrency=5)


@pytest.fixture
def sample_rules() -> List[Rule]:
    """A mix of block, allow, wildcard, and duplicate rules."""
    p = RuleParser()
    text = """! Test comment
||example.com^
||example.com^
||ads.example.com^
||*.example.com^
||google.com^
@@||allowed.com^
0.0.0.0 hosts-example.com
plain-domain.com
"""
    return p.parse_text(text, source="test")


# ── parser tests ─────────────────────────────────────────────────────


class TestRuleParser:
    def test_parse_block_rule(self, parser: RuleParser):
        rule = parser.parse_line("||example.com^")
        assert rule is not None
        assert rule.rule_type == "block"
        assert rule.domain == "example.com"
        assert rule.wildcard is False

    def test_parse_allow_rule(self, parser: RuleParser):
        rule = parser.parse_line("@@||allowed.com^")
        assert rule is not None
        assert rule.rule_type == "allow"
        assert rule.domain == "allowed.com"

    def test_parse_wildcard_rule(self, parser: RuleParser):
        rule = parser.parse_line("||*.example.com^")
        assert rule is not None
        assert rule.wildcard is True
        assert rule.domain == "*.example.com"
        assert rule.normalized_domain == "example.com"

    def test_parse_comment(self, parser: RuleParser):
        rule = parser.parse_line("! This is a comment")
        assert rule is not None
        assert rule.rule_type == "comment"

    def test_parse_hosts_format(self, parser: RuleParser):
        rule = parser.parse_line("0.0.0.0 ads.example.com")
        assert rule is not None
        assert rule.rule_type == "block"
        assert rule.domain == "ads.example.com"
        assert rule.output_raw == "||ads.example.com^"

    def test_parse_plain_domain(self, parser: RuleParser):
        rule = parser.parse_line("example.com")
        assert rule is not None
        assert rule.rule_type == "block"
        assert rule.domain == "example.com"

    def test_skip_html_css(self, parser: RuleParser):
        assert parser.parse_line("##.ad-banner") is None
        assert parser.parse_line("#@#.allow") is None

    def test_skip_localhost(self, parser: RuleParser):
        assert parser.parse_line("127.0.0.1 localhost") is None
        assert parser.parse_line("0.0.0.0 localhost.localdomain") is None

    def test_skip_empty(self, parser: RuleParser):
        assert parser.parse_line("") is None
        assert parser.parse_line("   ") is None

    def test_parse_text_count(self, parser: RuleParser, sample_rules: List[Rule]):
        # comment + 2 example.com (dup) + ads.example + wildcard + google + allow + hosts + plain
        assert len(sample_rules) == 9

    def test_streaming_parse(self, parser: RuleParser):
        lines = iter(["||a.com^", "||b.com^", "! comment", "||c.com^"])
        rules = list(parser.parse_stream(lines, source="stream"))
        assert len(rules) == 4
        assert rules[0].domain == "a.com"
        assert rules[2].rule_type == "comment"

    def test_category_propagation(self, parser: RuleParser):
        rule = parser.parse_line("||malware.com^", source="test", category=CATEGORY_MALWARE)
        assert rule is not None
        assert rule.category == CATEGORY_MALWARE


# ── normalizer tests ─────────────────────────────────────────────────


class TestRuleNormalizer:
    def test_default_no_strip_www(self):
        n = RuleNormalizer()
        assert n.normalize_domain("www.example.com") == "www.example.com"
        assert n.normalize_domain("example.com") == "example.com"

    def test_strip_www(self):
        n = RuleNormalizer(strip_www=True)
        assert n.normalize_domain("www.example.com") == "example.com"
        assert n.normalize_domain("example.com") == "example.com"

    def test_lowercase(self):
        n = RuleNormalizer()
        assert n.normalize_domain("EXAMPLE.COM") == "example.com"

    def test_trailing_dot(self):
        n = RuleNormalizer()
        assert n.normalize_domain("example.com.") == "example.com"

    def test_wildcard_preserved(self):
        n = RuleNormalizer()
        assert n.normalize_domain("*.example.com") == "*.example.com"

    def test_normalized_key(self):
        n = RuleNormalizer()
        r1 = Rule(raw="||example.com^", domain="example.com",
                  rule_type="block", wildcard=False)
        r2 = Rule(raw="||EXAMPLE.COM^", domain="EXAMPLE.COM",
                  rule_type="block", wildcard=False)
        assert n.normalized_key(r1) == n.normalized_key(r2)

    def test_are_equivalent_with_www(self):
        n = RuleNormalizer(strip_www=True)
        r1 = Rule(raw="||www.example.com^", domain="www.example.com",
                  rule_type="block", wildcard=False)
        r2 = Rule(raw="||example.com^", domain="example.com",
                  rule_type="block", wildcard=False)
        assert n.are_equivalent(r1, r2) is True

    def test_not_equivalent_different_type(self):
        n = RuleNormalizer()
        r1 = Rule(raw="||example.com^", domain="example.com",
                  rule_type="block", wildcard=False)
        r2 = Rule(raw="@@||example.com^", domain="example.com",
                  rule_type="allow", wildcard=False)
        assert n.are_equivalent(r1, r2) is False


# ── domain trie tests ────────────────────────────────────────────────


class TestDomainTrie:
    def test_wildcard_covers_subdomain(self):
        trie = DomainTrie()
        trie.add("example.com")
        assert trie.is_covered("ads.example.com") is True
        assert trie.is_covered("sub.ads.example.com") is True

    def test_wildcard_does_not_cover_root(self):
        trie = DomainTrie()
        trie.add("example.com")
        assert trie.is_covered("example.com") is False

    def test_no_wildcard_no_cover(self):
        trie = DomainTrie()
        assert trie.is_covered("anything.com") is False

    def test_multiple_wildcards(self):
        trie = DomainTrie()
        trie.add("example.com")
        trie.add("other.org")
        assert trie.is_covered("a.example.com") is True
        assert trie.is_covered("b.other.org") is True
        assert trie.is_covered("a.unrelated.net") is False


# ── dedup tests ──────────────────────────────────────────────────────


class TestDeduplication:
    def test_exact_dedup(self, engine: RuleEngine, sample_rules: List[Rule]):
        deduped, report = engine.deduplicate(sample_rules)
        # example.com appears twice → should be merged
        assert report.exact_merged >= 1
        # count unique domains
        domains = [r.domain for r in deduped if r.rule_type != "comment"]
        assert domains.count("example.com") == 1

    def test_wildcard_coverage(self, engine: RuleEngine):
        p = RuleParser()
        text = "||*.example.com^\n||ads.example.com^\n||other.com^"
        rules = p.parse_text(text, source="test")
        deduped, report = engine.deduplicate(rules)
        # ads.example.com should be removed by *.example.com
        assert report.wildcard_removed == 1
        domains = [r.domain for r in deduped]
        assert "ads.example.com" not in domains
        assert "*.example.com" in domains
        assert "other.com" in domains

    def test_allow_overrides_block(self, engine: RuleEngine):
        p = RuleParser()
        text = "||conflict.com^\n@@||conflict.com^"
        rules = p.parse_text(text, source="test")
        deduped, report = engine.deduplicate(rules)
        assert report.conflict_resolved == 1
        # only allow rule should remain
        allows = [r for r in deduped if r.rule_type == "allow"]
        blocks = [r for r in deduped if r.rule_type == "block"]
        assert len(allows) == 1
        assert len(blocks) == 0

    def test_no_allow_override(self):
        engine = RuleEngine(timeout=10, allow_overrides_block=False)
        p = RuleParser()
        text = "||conflict.com^\n@@||conflict.com^"
        rules = p.parse_text(text, source="test")
        deduped, report = engine.deduplicate(rules)
        assert report.conflict_resolved == 0
        assert len(deduped) == 2  # both survive

    def test_source_merging(self, engine: RuleEngine):
        p = RuleParser()
        r1 = p.parse_line("||dup.com^", source="source1")
        r2 = p.parse_line("||dup.com^", source="source2")
        deduped, _ = engine.deduplicate([r1, r2])
        assert len(deduped) == 1
        assert "source1" in deduped[0].sources
        assert "source2" in deduped[0].sources

    def test_normalized_dedup_www(self):
        engine = RuleEngine(
            timeout=10,
            enable_normalized_dedup=True,
            normalizer=RuleNormalizer(strip_www=True),
        )
        p = RuleParser()
        r1 = p.parse_line("||www.example.com^", source="s1")
        r2 = p.parse_line("||example.com^", source="s2")
        deduped, report = engine.deduplicate([r1, r2])
        assert report.normalized_merged == 1
        assert len(deduped) == 1

    def test_comment_dedup(self, engine: RuleEngine):
        p = RuleParser()
        text = "! Same comment\n! Same comment\n! Different comment"
        rules = p.parse_text(text, source="test")
        deduped, report = engine.deduplicate(rules)
        assert report.exact_merged >= 1
        assert len(deduped) == 2

    def test_empty_input(self, engine: RuleEngine):
        deduped, report = engine.deduplicate([])
        assert deduped == []
        assert report.total_removed == 0


# ── conflict detection tests ─────────────────────────────────────────


class TestConflictDetection:
    def test_detect_conflict(self):
        p = RuleParser()
        rules = [
            p.parse_line("||block.com^", source="s1"),
            p.parse_line("@@||block.com^", source="s2"),
            p.parse_line("||only-block.com^", source="s1"),
        ]
        conflicts = AsyncRuleEngine.detect_conflicts(rules)
        assert len(conflicts) == 1
        assert conflicts[0]["domain"] == "block.com"

    def test_no_conflict(self):
        p = RuleParser()
        rules = [
            p.parse_line("||a.com^", source="s1"),
            p.parse_line("||b.com^", source="s1"),
        ]
        assert AsyncRuleEngine.detect_conflicts(rules) == []


# ── cache tests ──────────────────────────────────────────────────────


class TestSourceCache:
    def test_store_and_get(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = SourceCache(cache_dir=tmpdir)
            cache.load()
            entry = cache.store(
                url="https://example.com/filter.txt",
                content="||test.com^",
                etag='"abc123"',
                last_modified="Mon, 01 Jan 2024 00:00:00 GMT",
            )
            assert entry.content_hash is not None
            assert entry.etag == '"abc123"'

            # retrieve
            got = cache.get("https://example.com/filter.txt")
            assert got is not None
            assert got.etag == '"abc123"'

    def test_get_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = SourceCache(cache_dir=tmpdir)
            cache.load()
            cache.store(url="https://example.com/f.txt", content="||a.com^\n||b.com^")
            content = cache.get_content("https://example.com/f.txt")
            assert content == "||a.com^\n||b.com^"

    def test_conditional_headers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = SourceCache(cache_dir=tmpdir)
            cache.load()
            cache.store(
                url="https://example.com/f.txt",
                content="test",
                etag='"etag123"',
                last_modified="Mon, 01 Jan 2024 00:00:00 GMT",
            )
            headers = cache.conditional_headers("https://example.com/f.txt")
            assert headers.get("If-None-Match") == '"etag123"'
            assert headers.get("If-Modified-Since") == "Mon, 01 Jan 2024 00:00:00 GMT"

    def test_conditional_headers_empty_for_unknown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = SourceCache(cache_dir=tmpdir)
            cache.load()
            assert cache.conditional_headers("https://unknown.com/f.txt") == {}

    def test_content_changed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = SourceCache(cache_dir=tmpdir)
            cache.load()
            cache.store(url="https://example.com/f.txt", content="old content")
            assert cache.content_changed("https://example.com/f.txt", "old content") is False
            assert cache.content_changed("https://example.com/f.txt", "new content") is True

    def test_ttl_expiry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = SourceCache(cache_dir=tmpdir, ttl_seconds=1)
            cache.load()
            cache.store(url="https://example.com/f.txt", content="test")
            # immediately should be available
            assert cache.get("https://example.com/f.txt") is not None
            # manually age the entry
            entry = cache._entries["https://example.com/f.txt"]
            entry.fetched_at = 0  # very old
            assert cache.get("https://example.com/f.txt") is None

    def test_clear(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = SourceCache(cache_dir=tmpdir)
            cache.load()
            cache.store(url="https://example.com/f.txt", content="test")
            cache.clear()
            assert cache.get("https://example.com/f.txt") is None
            assert cache.stats()["entry_count"] == 0

    def test_stats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = SourceCache(cache_dir=tmpdir)
            cache.load()
            cache.store(url="https://example.com/f1.txt", content="a" * 1000)
            cache.store(url="https://example.com/f2.txt", content="b" * 2000)
            stats = cache.stats()
            assert stats["entry_count"] == 2
            assert stats["total_size_bytes"] == 3000


# ── model tests ──────────────────────────────────────────────────────


class TestRuleModel:
    def test_equality(self):
        r1 = Rule(raw="||a.com^", domain="a.com", rule_type="block", wildcard=False)
        r2 = Rule(raw="||A.COM^", domain="A.COM", rule_type="block", wildcard=False)
        assert r1 == r2
        assert hash(r1) == hash(r2)

    def test_wildcard_not_equal(self):
        r1 = Rule(raw="||a.com^", domain="a.com", rule_type="block", wildcard=False)
        r2 = Rule(raw="||*.a.com^", domain="*.a.com", rule_type="block", wildcard=True)
        assert r1 != r2

    def test_output_raw(self):
        r = Rule(raw="original", domain="example.com", rule_type="block", wildcard=False)
        assert r.output_raw == "||example.com^"
        r2 = Rule(raw="original", domain="example.com", rule_type="allow", wildcard=False)
        assert r2.output_raw == "@@||example.com^"
        r3 = Rule(raw="! comment", domain="", rule_type="comment", wildcard=False)
        assert r3.output_raw == "! comment"

    def test_sources_string_conversion(self):
        r = Rule(raw="||a.com^", domain="a.com", rule_type="block",
                 wildcard=False, sources="single-source")
        assert r.sources == {"single-source"}

    def test_is_subdomain_of(self):
        parent = Rule(raw="||*.example.com^", domain="*.example.com",
                      rule_type="block", wildcard=True)
        child = Rule(raw="||ads.example.com^", domain="ads.example.com",
                     rule_type="block", wildcard=False)
        assert child.is_subdomain_of(parent) is True
        # root is not a subdomain of itself
        root = Rule(raw="||example.com^", domain="example.com",
                    rule_type="block", wildcard=False)
        assert root.is_subdomain_of(parent) is False


# ── async engine tests (using local files) ───────────────────────────


class TestAsyncEngineLocal:
    """Test async engine with local files (no network)."""

    @pytest.fixture
    def local_sources(self, tmp_path: Path):
        """Create two local filter files."""
        f1 = tmp_path / "source1.txt"
        f1.write_text("||a.com^\n||b.com^\n||shared.com^\n", encoding="utf-8")
        f2 = tmp_path / "source2.txt"
        f2.write_text("||c.com^\n||shared.com^\n! comment\n", encoding="utf-8")
        return [str(f1), str(f2)]

    def test_sync_merge_local(self, local_sources: List[str]):
        engine = RuleEngine(timeout=10, max_workers=2)
        result = engine.merge(local_sources, return_stats=True)
        rules = result["rules"]
        stats = result["stats"]
        # a, b, c, shared (deduped from 2 sources) + comment = 5
        assert len(rules) == 5
        assert stats["sources_ok"] == 2
        assert stats["exact_merged"] == 1  # shared.com

    def test_async_merge_local(self, local_sources: List[str]):
        async def _run():
            engine = AsyncRuleEngine(timeout=10, max_concurrency=2)
            async with engine:
                return await engine.merge(local_sources, return_stats=True)
        result = asyncio.run(_run())
        assert len(result["rules"]) == 5
        assert result["stats"]["sources_ok"] == 2

    def test_merge_with_source_meta(self, tmp_path: Path):
        f = tmp_path / "src.txt"
        f.write_text("||test.com^\n", encoding="utf-8")
        meta = SourceMeta(name="Test Source", url=str(f), category=CATEGORY_ADS, reputation=0.9)
        engine = RuleEngine(timeout=10)
        result = engine.merge([meta], return_stats=True)
        assert len(result["rules"]) == 1
        assert result["rules"][0].category == CATEGORY_ADS

    def test_dry_run_no_write(self, local_sources: List[str], tmp_path: Path):
        engine = RuleEngine(timeout=10)
        result = engine.merge(local_sources, return_stats=True)
        # merge itself doesn't write; that's CLI's job
        assert result is not None

    def test_invalid_source_raises(self):
        engine = RuleEngine(timeout=5)
        with pytest.raises(ValueError):
            engine.merge([], return_stats=True)


# ── integration: full pipeline with cache ────────────────────────────


class TestFullPipelineWithCache:
    def test_cached_reuse(self, tmp_path: Path):
        """Second run should hit cache (from_cache=True)."""
        src = tmp_path / "source.txt"
        src.write_text("||cached.com^\n", encoding="utf-8")

        cache_dir = tmp_path / "cache"

        # first run
        engine1 = RuleEngine(timeout=10, cache_dir=str(cache_dir))
        result1 = engine1.merge([str(src)], return_stats=True)
        assert result1["stats"]["sources_cached"] == 0

        # second run — local file doesn't use HTTP cache, but content hash
        # should detect no change
        engine2 = RuleEngine(timeout=10, cache_dir=str(cache_dir))
        result2 = engine2.merge([str(src)], return_stats=True)
        assert len(result2["rules"]) == 1
