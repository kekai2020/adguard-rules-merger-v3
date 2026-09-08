"""AdGuard Rules Merger v3 — async IO, streaming dedup, incremental cache."""

from .core import RuleEngine, DomainTrie, DedupReport
from .models import Rule
from .parser import RuleParser
from .reporter import MergeReporter
from .cache import SourceCache

__version__ = '3.0.0'
__all__ = [
    'RuleEngine', 'DomainTrie', 'DedupReport',
    'Rule', 'RuleParser', 'MergeReporter', 'SourceCache',
]
