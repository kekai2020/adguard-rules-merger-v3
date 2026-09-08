"""V3 Streaming parser — yields Rule objects one by one, never holds full list."""

from __future__ import annotations

import re
from typing import Iterator, Optional, Set

from .models import Rule


class RuleParser:
    """Stateless parser that yields rules as a generator."""

    RE_BLOCK   = re.compile(r'^\|\|([^/^\s]+)\^')
    RE_ALLOW   = re.compile(r'^@@\|\|([^/^\s]+)\^')
    RE_COMMENT = re.compile(r'^!')
    RE_WILD    = re.compile(r'^\*\.')
    RE_HOSTS   = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)')
    RE_DOMAIN  = re.compile(r'^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$')
    RE_HTML    = re.compile(r'^##')
    RE_CSS     = re.compile(r'^#@?#')
    RE_IPV6    = re.compile(r'^[0-9a-fA-F:]+$')
    LOCALHOST: Set[str] = frozenset({
        'localhost', 'localhost.localdomain',
        'localhost6', 'localhost6.localdomain6',
    })

    @classmethod
    def _is_ip(cls, text: str) -> bool:
        parts = text.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                pass
        return ':' in text and cls.RE_IPV6.match(text) is not None

    @staticmethod
    def _clean(domain: str) -> str:
        d = domain.lower().strip()
        return d[:-1] if d.endswith('.') else d

    def parse_line(self, line: str, source: str = '') -> Optional[Rule]:
        if not line:
            return None
        s = line.strip()
        if not s:
            return None

        if self.RE_COMMENT.match(s):
            return Rule(raw=s, domain='', rule_type='comment', wildcard=False, sources={source})

        if self.RE_HTML.match(s) or self.RE_CSS.match(s):
            return None

        m = self.RE_ALLOW.match(s)
        if m:
            d = self._clean(m.group(1))
            return Rule(raw=s, domain=d, rule_type='allow',
                        wildcard=self.RE_WILD.match(d) is not None, sources={source})

        m = self.RE_BLOCK.match(s)
        if m:
            d = self._clean(m.group(1))
            return Rule(raw=s, domain=d, rule_type='block',
                        wildcard=self.RE_WILD.match(d) is not None, sources={source})

        m = self.RE_HOSTS.match(s)
        if m:
            d = self._clean(m.group(1))
            if d not in self.LOCALHOST:
                return Rule(raw=f'||{d}^', domain=d, rule_type='block',
                            wildcard=False, sources={source})
            return None

        if self.RE_DOMAIN.match(s) and not self._is_ip(s):
            d = self._clean(s)
            return Rule(raw=f'||{d}^', domain=d, rule_type='block',
                        wildcard=False, sources={source})

        return None

    def parse_iter(self, text: str, source: str = '') -> Iterator[Rule]:
        """Streaming parse — yields rules one by one."""
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

        for line in text.splitlines():
            if not line:
                continue
            s = line.strip()
            if not s:
                continue

            if re_comment(s):
                yield RuleCls(raw=s, domain='', rule_type='comment',
                              wildcard=False, sources={source})
                continue

            if re_html(s) or re_css(s):
                continue

            m = re_allow(s)
            if m:
                d = clean(m.group(1))
                yield RuleCls(raw=s, domain=d, rule_type='allow',
                              wildcard=re_wild(d) is not None, sources={source})
                continue

            m = re_block(s)
            if m:
                d = clean(m.group(1))
                yield RuleCls(raw=s, domain=d, rule_type='block',
                              wildcard=re_wild(d) is not None, sources={source})
                continue

            m = re_hosts(s)
            if m:
                d = clean(m.group(1))
                if d not in localhost:
                    yield RuleCls(raw=f'||{d}^', domain=d, rule_type='block',
                                  wildcard=False, sources={source})
                continue

            if re_plain(s) and not is_ip(s):
                d = clean(s)
                yield RuleCls(raw=f'||{d}^', domain=d, rule_type='block',
                              wildcard=False, sources={source})

    def parse_text(self, text: str, source: str = '') -> list[Rule]:
        """Backward-compatible: returns list."""
        return list(self.parse_iter(text, source))
