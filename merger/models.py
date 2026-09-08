"""V3 Data models — slots-optimized, consistent equality."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Set


@dataclass
class Rule:
    """A single AdGuard filter rule with full provenance.

    __eq__ / __hash__ use (normalized_domain, rule_type, wildcard).
    *.a.com and a.com are NOT equal — they are semantically different.
    """

    raw: str
    domain: str
    rule_type: str          # 'block' | 'allow' | 'comment'
    wildcard: bool
    sources: Set[str] = field(default_factory=set)
    _norm: str = field(init=False, repr=False, compare=False, default="")

    def __post_init__(self) -> None:
        if isinstance(self.sources, str):
            self.sources = {self.sources}
        self._norm = self._normalize(self.domain)

    @staticmethod
    def _normalize(domain: str) -> str:
        d = domain.lower().strip()
        if d.startswith('*.'):
            d = d[2:]
        if d.endswith('.'):
            d = d[:-1]
        return d

    @property
    def normalized_domain(self) -> str:
        return self._norm

    @property
    def output_raw(self) -> str:
        if self.rule_type == 'comment':
            return self.raw
        if self.rule_type == 'allow':
            return f'@@||{self.domain}^'
        return f'||{self.domain}^'

    def is_subdomain_of(self, parent: 'Rule') -> bool:
        if not parent.wildcard or self.rule_type != parent.rule_type:
            return False
        return (self._norm != parent._norm and
                self._norm.endswith('.' + parent._norm))

    def covers_as_wildcard(self, child: 'Rule') -> bool:
        if not self.wildcard or self.rule_type != child.rule_type:
            return False
        return (child._norm != self._norm and
                child._norm.endswith('.' + self._norm))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Rule):
            return NotImplemented
        return (self._norm == other._norm and
                self.rule_type == other.rule_type and
                self.wildcard == other.wildcard)

    def __hash__(self) -> int:
        return hash((self._norm, self.rule_type, self.wildcard))

    def __str__(self) -> str:
        return self.output_raw

    def __repr__(self) -> str:
        src = ','.join(sorted(self.sources)[:2])
        if len(self.sources) > 2:
            src += ',...'
        return f'Rule({self.rule_type} {self.domain!r} [{src}])'
