"""V3 Report generator with per-source attribution."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Rule


class MergeReporter:

    def __init__(self, rules: List[Rule], stats: Optional[Dict[str, Any]] = None) -> None:
        self.rules = rules
        self.stats = stats or {}

    def _source_counts(self) -> Counter:
        c: Counter = Counter()
        for r in self.rules:
            for s in r.sources:
                c[s] += 1
        return c

    def _type_counts(self) -> Counter:
        return Counter(r.rule_type for r in self.rules)

    def generate_markdown(self, title: str = 'AdGuard Rules Merge Report') -> str:
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        lines = [f'# {title}', '', f'**Generated:** {now} UTC', '', '## Summary', '']

        if self.stats:
            s = self.stats
            lines += [
                '| Metric | Value |', '|--------|-------|',
                f'| Rules before dedup | {s.get("total_before", "N/A"):,} |',
                f'| Rules after dedup | {s.get("total_after", "N/A"):,} |',
                f'| Deduplication rate | {s.get("dedup_rate", 0):.1f}% |',
                f'| Sources loaded | {s.get("sources_ok", 0)} / {s.get("sources_total", 0)} |',
                f'| Cache hits | {s.get("cache_hits", 0)} |',
                f'| Processing time | {s.get("elapsed_time", 0):.2f}s |',
                f'| Exact merges | {s.get("exact_merged", 0):,} |',
                f'| Wildcard removals | {s.get("wildcard_removed", 0):,} |',
                f'| Conflicts resolved | {s.get("conflict_resolved", 0):,} |',
                '',
                '### Rule Breakdown', '',
                f'- **Block:** {s.get("block_count", 0):,}',
                f'- **Allow:** {s.get("allow_count", 0):,}',
                f'- **Comment:** {s.get("comment_count", 0):,}', '',
            ]

        src_counts = self._source_counts()
        if src_counts:
            lines += ['## Per-Source Attribution', '',
                       '| Source | Rules |', '|--------|-------|']
            for src, cnt in src_counts.most_common(20):
                label = src if len(src) < 70 else src[:67] + '...'
                lines.append(f'| `{label}` | {cnt:,} |')
            lines.append('')

        return '\n'.join(lines)

    def generate_json(self) -> Dict[str, Any]:
        return {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'summary': {'total_rules': len(self.rules), **self.stats},
            'per_source': dict(self._source_counts().most_common()),
            'per_type': dict(self._type_counts()),
        }

    def generate_text(self) -> str:
        lines = ['=' * 60, 'AdGuard Rules Merge Report', '=' * 60, '']
        if self.stats:
            s = self.stats
            lines += [
                'SUMMARY', '-' * 40,
                f'Before:   {s.get("total_before", "N/A"):,}',
                f'After:    {s.get("total_after", "N/A"):,}',
                f'Dedup:    {s.get("dedup_rate", 0):.1f}%',
                f'Sources:  {s.get("sources_ok", 0)}/{s.get("sources_total", 0)}',
                f'Cache:    {s.get("cache_hits", 0)} hits',
                f'Time:     {s.get("elapsed_time", 0):.2f}s', '',
            ]
        return '\n'.join(lines)

    def save(self, path: str, fmt: str = 'markdown') -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if fmt == 'markdown':
            content = self.generate_markdown()
        elif fmt == 'text':
            content = self.generate_text()
        elif fmt == 'json':
            content = json.dumps(self.generate_json(), indent=2, ensure_ascii=False)
        else:
            raise ValueError(f'Unknown format: {fmt}')
        p.write_text(content, encoding='utf-8')
