"""V3 Streaming parser for AdGuard filter rules.

Key changes from V2:
  - parse_stream() is a generator that yields Rule objects line-by-line,
    enabling true streaming (边下载边解析边去重).
  - parse_text() retained for backward compatibility and small files.
  - Source category is propagated to each Rule for tiered output.
  - Optimized hot loop with local variable binding.

Supported input formats:
  - AdGuard:  ||domain.com^  /  @@||domain.com^  /  ! comment
  - Hosts:    0.0.0.0 domain  /  127.0.0.1 domain
  - Plain:    domain.com  (auto-converted to block rule)
  - Adblock+: ##selector  /  #@#selector  (skipped)
  - IP-block: 0.0.0.0 / 127.0.0.1 with localhost filtering
"""

from __future__ import annotations

import re
from typing import Iterator, List, Optional, Set

from .models import Rule, CATEGORY_OTHER, CATEGORY_COMMENT


class RuleParser:
    """Stateless, high-performance streaming parser for filter rules."""

    # ── pre-compiled patterns ──────────────────────────────────

    RE_BLOCK   = re.compile(r"^\|\|([^/^\s]+)\^")
    RE_ALLOW   = re.compile(r"^@@\|\|([^/^\s]+)\^")
    RE_COMMENT = re.compile(r"^!")
    RE_WILD    = re.compile(r"^\*\.")
    RE_HOSTS   = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)")
    RE_DOMAIN  = re.compile(r"^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")
    RE_HTML    = re.compile(r"^##")
    RE_CSS     = re.compile(r"^#@?#")
    RE_IPV6    = re.compile(r"^[0-9a-fA-F:]+$")

    LOCALHOST: Set[str] = frozenset({
        "localhost", "localhost.localdomain",
        "localhost6", "localhost6.localdomain6",
    })

    # ── helpers ────────────────────────────────────────────────

    @classmethod
    def _is_ip(cls, text: str) -> bool:
        """Check for IPv4 or IPv6 address."""
        parts = text.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                pass
        if ":" in text and cls.RE_IPV6.match(text):
            return True
        return False

    @staticmethod
    def _clean(domain: str) -> str:
        d = domain.lower().strip()
        if d.endswith("."):
            d = d[:-1]
        return d

    # ── single-line parse ──────────────────────────────────────

    def parse_line(
        self,
        line: str,
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> Optional[Rule]:
        """Parse one line.  Returns Rule or None (skip)."""
        if not line:
            return None
        s = line.strip()
        if not s:
            return None

        # comment
        if self.RE_COMMENT.match(s):
            return Rule(raw=s, domain="", rule_type="comment",
                        wildcard=False, sources={source},
                        category=CATEGORY_COMMENT)

        # skip HTML / CSS selectors
        if self.RE_HTML.match(s) or self.RE_CSS.match(s):
            return None

        # allow: @@||domain^
        m = self.RE_ALLOW.match(s)
        if m:
            d = self._clean(m.group(1))
            return Rule(raw=s, domain=d, rule_type="allow",
                        wildcard=self.RE_WILD.match(d) is not None,
                        sources={source}, category=category)

        # block: ||domain^
        m = self.RE_BLOCK.match(s)
        if m:
            d = self._clean(m.group(1))
            return Rule(raw=s, domain=d, rule_type="block",
                        wildcard=self.RE_WILD.match(d) is not None,
                        sources={source}, category=category)

        # hosts: 0.0.0.0 / 127.0.0.1
        m = self.RE_HOSTS.match(s)
        if m:
            d = self._clean(m.group(1))
            if d in self.LOCALHOST:
                return None
            return Rule(raw=f"||{d}^", domain=d, rule_type="block",
                        wildcard=False, sources={source}, category=category)

        # plain domain
        if self.RE_DOMAIN.match(s) and not self._is_ip(s):
            d = self._clean(s)
            return Rule(raw=f"||{d}^", domain=d, rule_type="block",
                        wildcard=False, sources={source}, category=category)

        return None

    # ── streaming parse (V3 core) ──────────────────────────────

    def parse_stream(
        self,
        lines: Iterator[str],
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> Iterator[Rule]:
        """Parse rules from a line iterator, yielding one Rule at a time.

        This is the V3 streaming entry point.  It never materializes the
        full rule list in memory — each rule is yielded as soon as it is
        parsed, enabling pipeline parallelism (download → parse → dedup).

        Args:
            lines:    Iterator yielding raw text lines (e.g. file object,
                      aiohttp response content split by lines).
            source:   Source URL/identifier for provenance tracking.
            category: Source category propagated to each Rule.

        Yields:
            Rule objects (comments included; skips invalid lines).
        """
        # local refs for speed in hot loop
        re_comment = self.RE_COMMENT.match
        re_allow   = self.RE_ALLOW.match
        re_block   = self.RE_BLOCK.match
        re_hosts   = self.RE_HOSTS.match
        re_plain   = self.RE_DOMAIN.match
        re_html    = self.RE_HTML.match
        re_css     = self.RE_CSS.match
        re_wild    = self.RE_WILD.match
        clean      = self._clean
        is_ip      = self._is_ip
        localhost  = self.LOCALHOST
        RuleCls    = Rule
        cat_comment = CATEGORY_COMMENT

        for line in lines:
            if not line:
                continue
            s = line.strip()
            if not s:
                continue

            if re_comment(s):
                yield RuleCls(raw=s, domain="", rule_type="comment",
                               wildcard=False, sources={source},
                               category=cat_comment)
                continue

            if re_html(s) or re_css(s):
                continue

            m = re_allow(s)
            if m:
                d = clean(m.group(1))
                yield RuleCls(raw=s, domain=d, rule_type="allow",
                              wildcard=re_wild(d) is not None,
                              sources={source}, category=category)
                continue

            m = re_block(s)
            if m:
                d = clean(m.group(1))
                yield RuleCls(raw=s, domain=d, rule_type="block",
                              wildcard=re_wild(d) is not None,
                              sources={source}, category=category)
                continue

            m = re_hosts(s)
            if m:
                d = clean(m.group(1))
                if d not in localhost:
                    yield RuleCls(raw=f"||{d}^", domain=d, rule_type="block",
                                   wildcard=False, sources={source},
                                   category=category)
                continue

            if re_plain(s) and not is_ip(s):
                d = clean(s)
                yield RuleCls(raw=f"||{d}^", domain=d, rule_type="block",
                              wildcard=False, sources={source},
                              category=category)
                continue

    # ── bulk parse (V2 compatible) ─────────────────────────────

    def parse_text(
        self,
        text: str,
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> List[Rule]:
        """Parse full text of a filter list (materializes all rules).

        Retained for V2 compatibility and small files.  For large files,
        prefer parse_stream() to avoid loading everything into memory.
        """
        return list(self.parse_stream(iter(text.splitlines()), source, category))
