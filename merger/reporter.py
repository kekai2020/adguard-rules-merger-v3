"""V3 Report generator — enhanced with stats.json and per-category breakdown."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Rule


class MergeReporter:
    """Generates human-readable and machine-readable merge reports."""

    def __init__(
        self,
        rules: List[Rule],
        stats: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.rules = rules
        self.stats = stats or {}

    # ── helpers ──────────────────────────────────────────────────

    def _source_counts(self) -> Counter:
        c: Counter = Counter()
        for r in self.rules:
            for s in r.sources:
                c[s] += 1
        return c

    def _type_counts(self) -> Counter:
        return Counter(r.rule_type for r in self.rules)

    def _category_counts(self) -> Counter:
        return Counter(r.category for r in self.rules)

    def _tld_counts(self, top_n: int = 20) -> Counter:
        c: Counter = Counter()
        for r in self.rules:
            if r.rule_type == "comment" or not r.domain:
                continue
            d = r.domain.lstrip("*.")
            parts = d.rsplit(".", 1)
            if len(parts) == 2:
                c[parts[1]] += 1
        return Counter(dict(c.most_common(top_n)))

    # ── markdown ─────────────────────────────────────────────────

    def generate_markdown(self, title: str = "AdGuard Rules Merge Report (V3)") -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# {title}", "",
            f"**Generated:** {now} UTC", "",
            "## Summary", "",
        ]

        if self.stats:
            s = self.stats
            lines += [
                "| Metric | Value |",
                "|--------|-------|",
                f"| Rules before dedup | {s.get('total_before', 'N/A'):,} |",
                f"| Rules after dedup | {s.get('total_after', 'N/A'):,} |",
                f"| Deduplication rate | {s.get('dedup_rate', 0):.1f}% |",
                f"| Sources loaded | {s.get('sources_ok', 0)} / {s.get('sources_total', 0)} |",
                f"| Sources from cache | {s.get('sources_cached', 0)} |",
                f"| Processing time | {s.get('elapsed_time', 0):.2f}s |",
                f"| Exact merges | {s.get('exact_merged', 0):,} |",
                f"| Normalized merges | {s.get('normalized_merged', 0):,} |",
                f"| Wildcard removals | {s.get('wildcard_removed', 0):,} |",
                f"| Conflicts resolved | {s.get('conflict_resolved', 0):,} |",
                "",
                "### Rule Breakdown", "",
                f"- **Block:** {s.get('block_count', 0):,}",
                f"- **Allow:** {s.get('allow_count', 0):,}",
                f"- **Comment:** {s.get('comment_count', 0):,}",
                "",
            ]

        # per-source attribution
        src_counts = self._source_counts()
        if src_counts:
            lines += ["## Per-Source Attribution", "",
                       "| Source | Rules contributed |",
                       "|--------|-------------------|"]
            for src, cnt in src_counts.most_common(20):
                label = src if len(src) < 70 else src[:67] + "..."
                lines.append(f"| `{label}` | {cnt:,} |")
            lines.append("")

        # category distribution
        cat_counts = self._category_counts()
        if cat_counts:
            lines += ["## Category Distribution", "",
                       "| Category | Count | Percentage |",
                       "|----------|-------|------------|"]
            total = len(self.rules) or 1
            for cat, cnt in cat_counts.most_common():
                pct = cnt / total * 100
                lines.append(f"| {cat} | {cnt:,} | {pct:.1f}% |")
            lines.append("")

        # TLD distribution
        tld_counts = self._tld_counts()
        if tld_counts:
            lines += ["## Top 20 TLDs", "",
                       "| TLD | Count |",
                       "|-----|-------|"]
            for tld, cnt in tld_counts.most_common():
                lines.append(f"| .{tld} | {cnt:,} |")
            lines.append("")

        # type distribution
        type_counts = self._type_counts()
        if type_counts:
            lines += ["## Type Distribution", ""]
            total = len(self.rules) or 1
            for t, c in type_counts.most_common():
                pct = c / total * 100
                bar = "█" * int(pct / 5)
                lines.append(f"- **{t}:** {c:,} ({pct:.1f}%) {bar}")
            lines.append("")

        return "\n".join(lines)

    # ── json (stats.json compatible) ─────────────────────────────

    def generate_json(self) -> Dict[str, Any]:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {"total_rules": len(self.rules), **self.stats},
            "per_source": dict(self._source_counts().most_common()),
            "per_type": dict(self._type_counts()),
            "per_category": dict(self._category_counts()),
            "top_tlds": dict(self._tld_counts()),
        }

    # ── text ─────────────────────────────────────────────────────

    def generate_text(self) -> str:
        lines = [
            "=" * 60,
            "AdGuard Rules Merge Report (V3)",
            "=" * 60,
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
            "",
        ]
        if self.stats:
            s = self.stats
            lines += [
                "SUMMARY", "-" * 40,
                f"Before:           {s.get('total_before', 'N/A'):,}",
                f"After:            {s.get('total_after', 'N/A'):,}",
                f"Dedup rate:       {s.get('dedup_rate', 0):.1f}%",
                f"Sources:          {s.get('sources_ok', 0)}/{s.get('sources_total', 0)}",
                f"Cached:           {s.get('sources_cached', 0)}",
                f"Time:             {s.get('elapsed_time', 0):.2f}s",
                f"Exact merge:      {s.get('exact_merged', 0):,}",
                f"Normalized merge: {s.get('normalized_merged', 0):,}",
                f"Wildcard:         {s.get('wildcard_removed', 0):,}",
                f"Conflicts:        {s.get('conflict_resolved', 0):,}",
                "",
                "RULE TYPES", "-" * 40,
                f"Block:   {s.get('block_count', 0):,}",
                f"Allow:   {s.get('allow_count', 0):,}",
                f"Comment: {s.get('comment_count', 0):,}",
                "",
            ]
        return "\n".join(lines)

    # ── save ──────────────────────────────────────────────────────

    def save(self, path: str, fmt: str = "markdown") -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "markdown":
            content = self.generate_markdown()
        elif fmt == "text":
            content = self.generate_text()
        elif fmt == "json":
            content = json.dumps(self.generate_json(), indent=2, ensure_ascii=False)
        else:
            raise ValueError(f"Unknown format: {fmt}")

        p.write_text(content, encoding="utf-8")
