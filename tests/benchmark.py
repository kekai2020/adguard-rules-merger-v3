"""V3 Performance benchmarks — compare V2 vs V3 and track regressions.

Run with: pytest tests/benchmark.py --benchmark-only
Or: python -m pytest tests/benchmark.py --benchmark-autosave
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from merger import RuleEngine, RuleParser, Rule, AsyncRuleEngine
from merger.models import SourceMeta


# ── helpers ──────────────────────────────────────────────────────────


def generate_large_rule_set(num_rules: int = 100000, num_sources: int = 5) -> List[str]:
    """Generate a large set of synthetic rules for benchmarking."""
    import random
    import string

    random.seed(42)
    sources = []
    for src_idx in range(num_sources):
        lines = []
        for i in range(num_rules // num_sources):
            # mix of rule types
            r = random.random()
            if r < 0.7:
                # block rule
                domain = f"domain{i}-{src_idx}.example.com"
                lines.append(f"||{domain}^")
            elif r < 0.85:
                # wildcard
                domain = f"wild{i}.example.com"
                lines.append(f"||*.{domain}^")
            elif r < 0.95:
                # allow
                domain = f"allow{i}.example.com"
                lines.append(f"@@||{domain}^")
            else:
                # comment
                lines.append(f"! Rule {i} from source {src_idx}")
        sources.append("\n".join(lines))
    return sources


def write_temp_sources(texts: List[str], tmpdir: str) -> List[str]:
    paths = []
    for i, text in enumerate(texts):
        p = Path(tmpdir) / f"source_{i}.txt"
        p.write_text(text, encoding="utf-8")
        paths.append(str(p))
    return paths


# ── parser benchmarks ────────────────────────────────────────────────


class TestParserBenchmark:
    @pytest.fixture
    def large_text(self) -> str:
        texts = generate_large_rule_set(50000, 1)
        return texts[0]

    def test_parse_text_50k(self, benchmark, large_text: str):
        parser = RuleParser()
        result = benchmark(parser.parse_text, large_text, source="bench")
        assert len(result) > 0

    def test_parse_stream_50k(self, benchmark, large_text: str):
        parser = RuleParser()
        def _stream():
            return list(parser.parse_stream(iter(large_text.splitlines()), source="bench"))
        result = benchmark(_stream)
        assert len(result) > 0


# ── dedup benchmarks ─────────────────────────────────────────────────


class TestDedupBenchmark:
    @pytest.fixture
    def large_rules(self) -> List[Rule]:
        texts = generate_large_rule_set(100000, 5)
        parser = RuleParser()
        rules = []
        for i, text in enumerate(texts):
            rules.extend(parser.parse_text(text, source=f"src{i}"))
        return rules

    def test_dedup_100k(self, benchmark, large_rules: List[Rule]):
        engine = RuleEngine(timeout=10)
        result = benchmark(engine.deduplicate, large_rules)
        assert result is not None

    def test_dedup_with_normalized(self, benchmark, large_rules: List[Rule]):
        from merger import RuleNormalizer
        engine = RuleEngine(
            timeout=10,
            enable_normalized_dedup=True,
            normalizer=RuleNormalizer(strip_www=True),
        )
        result = benchmark(engine.deduplicate, large_rules)
        assert result is not None


# ── full merge benchmarks ────────────────────────────────────────────


class TestFullMergeBenchmark:
    def test_merge_5_sources_100k(self, benchmark):
        with tempfile.TemporaryDirectory() as tmpdir:
            texts = generate_large_rule_set(100000, 5)
            sources = write_temp_sources(texts, tmpdir)

            def _merge():
                engine = RuleEngine(timeout=30, max_workers=5)
                return engine.merge(sources, return_stats=True)

            result = benchmark(_merge)
            assert result["stats"]["sources_ok"] == 5

    def test_merge_with_cache(self, benchmark):
        with tempfile.TemporaryDirectory() as tmpdir:
            texts = generate_large_rule_set(50000, 3)
            sources = write_temp_sources(texts, tmpdir)
            cache_dir = str(Path(tmpdir) / "cache")

            def _merge():
                engine = RuleEngine(timeout=30, max_workers=3, cache_dir=cache_dir)
                return engine.merge(sources, return_stats=True)

            result = benchmark(_merge)
            assert result["stats"]["sources_ok"] == 3
