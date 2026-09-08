"""V3 test suite — covers models, parser, trie, dedup, cache, async."""

import asyncio
import json
import pytest
from pathlib import Path

from merger.models import Rule
from merger.parser import RuleParser
from merger.core import RuleEngine, DomainTrie, DedupReport
from merger.cache import SourceCache


# ═══════════════════════════════════════════════════════════════
#  Rule model
# ═══════════════════════════════════════════════════════════════


class TestRuleModel:
    def test_basic(self):
        r = Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources={'s1'})
        assert r.normalized_domain == 'a.com'
        assert r.output_raw == '||a.com^'

    def test_wildcard_strip(self):
        r = Rule(raw='||*.a.com^', domain='*.a.com', rule_type='block',
                 wildcard=True, sources={'s1'})
        assert r.normalized_domain == 'a.com'
        assert r.wildcard

    def test_trailing_dot(self):
        r = Rule(raw='||a.com.^', domain='a.com.', rule_type='block',
                 wildcard=False, sources={'s1'})
        assert r.normalized_domain == 'a.com'

    def test_case_insensitive(self):
        r = Rule(raw='||Example.COM^', domain='Example.COM',
                 rule_type='block', wildcard=False, sources={'s1'})
        assert r.normalized_domain == 'example.com'

    def test_output_raw_allow(self):
        r = Rule(raw='@@||a.com^', domain='a.com', rule_type='allow',
                 wildcard=False, sources={'s1'})
        assert r.output_raw == '@@||a.com^'

    def test_output_raw_comment(self):
        r = Rule(raw='! comment', domain='', rule_type='comment',
                 wildcard=False, sources={'s1'})
        assert r.output_raw == '! comment'

    def test_eq_same(self):
        r1 = Rule(raw='||a.com^', domain='a.com', rule_type='block',
                  wildcard=False, sources={'s1'})
        r2 = Rule(raw='||a.com^', domain='a.com', rule_type='block',
                  wildcard=False, sources={'s2'})
        assert r1 == r2
        assert hash(r1) == hash(r2)

    def test_eq_wildcard_vs_not(self):
        r1 = Rule(raw='||*.a.com^', domain='*.a.com', rule_type='block',
                  wildcard=True, sources={'s1'})
        r2 = Rule(raw='||a.com^', domain='a.com', rule_type='block',
                  wildcard=False, sources={'s1'})
        assert r1 != r2

    def test_sources_string_coerce(self):
        r = Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources='s1')
        assert r.sources == {'s1'}

    def test_covers_as_wildcard(self):
        wc = Rule(raw='||*.a.com^', domain='*.a.com', rule_type='block',
                  wildcard=True, sources={'s1'})
        sub = Rule(raw='||x.a.com^', domain='x.a.com', rule_type='block',
                   wildcard=False, sources={'s1'})
        assert wc.covers_as_wildcard(sub)
        assert not sub.covers_as_wildcard(wc)

    def test_self_not_covered(self):
        wc = Rule(raw='||*.a.com^', domain='*.a.com', rule_type='block',
                  wildcard=True, sources={'s1'})
        exact = Rule(raw='||a.com^', domain='a.com', rule_type='block',
                     wildcard=False, sources={'s1'})
        assert not wc.covers_as_wildcard(exact)


# ═══════════════════════════════════════════════════════════════
#  Parser
# ═══════════════════════════════════════════════════════════════


class TestParser:
    def setup_method(self):
        self.p = RuleParser()

    def test_block(self):
        r = self.p.parse_line('||example.com^')
        assert r and r.rule_type == 'block'

    def test_allow(self):
        r = self.p.parse_line('@@||example.com^')
        assert r and r.rule_type == 'allow'

    def test_comment(self):
        r = self.p.parse_line('! comment')
        assert r and r.rule_type == 'comment'

    def test_wildcard(self):
        r = self.p.parse_line('||*.example.com^')
        assert r and r.wildcard and r.normalized_domain == 'example.com'

    def test_hosts(self):
        r = self.p.parse_line('0.0.0.0 example.com')
        assert r and r.rule_type == 'block' and r.raw == '||example.com^'

    def test_plain_domain(self):
        r = self.p.parse_line('example.com')
        assert r and r.rule_type == 'block'

    def test_localhost_skip(self):
        assert self.p.parse_line('0.0.0.0 localhost') is None
        assert self.p.parse_line('0.0.0.0 localhost6') is None

    def test_empty(self):
        assert self.p.parse_line('') is None

    def test_html_skip(self):
        assert self.p.parse_line('##.ad') is None

    def test_ipv4_skip(self):
        assert self.p.parse_line('192.168.1.1') is None

    def test_ipv6_skip(self):
        assert self.p.parse_line('::1') is None

    def test_hosts_with_comment(self):
        r = self.p.parse_line('0.0.0.0 example.com # comment')
        assert r and r.domain == 'example.com'

    def test_parse_iter_generator(self):
        text = '! c\n||a.com^\n@@||b.com^\n0.0.0.0 c.com\n'
        rules = list(self.p.parse_iter(text, source='test'))
        assert len(rules) == 4
        types = [r.rule_type for r in rules]
        assert types.count('block') == 2
        assert types.count('allow') == 1
        assert types.count('comment') == 1

    def test_parse_text_list(self):
        text = '! c\n||a.com^\n'
        rules = self.p.parse_text(text, source='test')
        assert isinstance(rules, list)
        assert len(rules) == 2


# ═══════════════════════════════════════════════════════════════
#  DomainTrie
# ═══════════════════════════════════════════════════════════════


class TestDomainTrie:
    def test_basic_coverage(self):
        t = DomainTrie()
        t.add('example.com')
        assert t.is_covered('sub.example.com')
        assert t.is_covered('deep.sub.example.com')

    def test_self_not_covered(self):
        t = DomainTrie()
        t.add('example.com')
        assert not t.is_covered('example.com')

    def test_unrelated(self):
        t = DomainTrie()
        t.add('example.com')
        assert not t.is_covered('other.org')

    def test_multiple(self):
        t = DomainTrie()
        t.add('a.com')
        t.add('b.com')
        assert t.is_covered('x.a.com')
        assert t.is_covered('x.b.com')
        assert not t.is_covered('x.c.com')

    def test_empty(self):
        t = DomainTrie()
        assert not t.is_covered('anything.com')


# ═══════════════════════════════════════════════════════════════
#  Engine dedup
# ═══════════════════════════════════════════════════════════════


class TestEngineDedup:
    def setup_method(self):
        self.engine = RuleEngine(allow_overrides_block=False, use_cache=False)

    def _dedup(self, rules):
        return self.engine.deduplicate(iter(rules))

    def test_exact_dedup(self):
        rules = [
            Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources={'s1'}),
            Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources={'s2'}),
        ]
        out, report = self._dedup(rules)
        assert len(out) == 1
        assert report.exact_merged == 1
        assert out[0].sources == {'s1', 's2'}

    def test_wildcard_removes_subdomain(self):
        rules = [
            Rule(raw='||*.a.com^', domain='*.a.com', rule_type='block',
                 wildcard=True, sources={'s1'}),
            Rule(raw='||sub.a.com^', domain='sub.a.com', rule_type='block',
                 wildcard=False, sources={'s2'}),
        ]
        out, report = self._dedup(rules)
        assert len(out) == 1
        assert out[0].wildcard
        assert report.wildcard_removed == 1

    def test_wildcard_keeps_parent(self):
        rules = [
            Rule(raw='||*.a.com^', domain='*.a.com', rule_type='block',
                 wildcard=True, sources={'s1'}),
            Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources={'s2'}),
        ]
        out, _ = self._dedup(rules)
        assert len(out) == 2

    def test_block_allow_separate(self):
        rules = [
            Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources={'s1'}),
            Rule(raw='@@||a.com^', domain='a.com', rule_type='allow',
                 wildcard=False, sources={'s1'}),
        ]
        out, _ = self._dedup(rules)
        assert len(out) == 2

    def test_comment_dedup(self):
        rules = [
            Rule(raw='! c', domain='', rule_type='comment',
                 wildcard=False, sources={'s1'}),
            Rule(raw='! c', domain='', rule_type='comment',
                 wildcard=False, sources={'s2'}),
        ]
        out, _ = self._dedup(rules)
        assert len(out) == 1

    def test_empty(self):
        out, report = self._dedup([])
        assert out == []
        assert report.total_removed == 0

    def test_full_pipeline(self):
        rules = [
            Rule(raw='||*.a.com^', domain='*.a.com', rule_type='block',
                 wildcard=True, sources={'s1'}),
            Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources={'s1'}),
            Rule(raw='||b.com^', domain='b.com', rule_type='block',
                 wildcard=False, sources={'s1'}),
            Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources={'s2'}),
            Rule(raw='||sub.a.com^', domain='sub.a.com', rule_type='block',
                 wildcard=False, sources={'s2'}),
            Rule(raw='||c.com^', domain='c.com', rule_type='block',
                 wildcard=False, sources={'s2'}),
        ]
        out, report = self._dedup(rules)
        domains = {r.normalized_domain for r in out}
        assert domains == {'a.com', 'b.com', 'c.com'}
        assert report.exact_merged == 1
        assert report.wildcard_removed == 1


# ═══════════════════════════════════════════════════════════════
#  Conflict resolution
# ═══════════════════════════════════════════════════════════════


class TestConflictResolution:
    def test_allow_overrides_block(self):
        engine = RuleEngine(allow_overrides_block=True, use_cache=False)
        rules = [
            Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources={'s1'}),
            Rule(raw='@@||a.com^', domain='a.com', rule_type='allow',
                 wildcard=False, sources={'s2'}),
        ]
        out, report = engine.deduplicate(iter(rules))
        assert len(out) == 1
        assert out[0].rule_type == 'allow'
        assert out[0].sources == {'s1', 's2'}
        assert report.conflict_resolved == 1

    def test_no_override_when_disabled(self):
        engine = RuleEngine(allow_overrides_block=False, use_cache=False)
        rules = [
            Rule(raw='||a.com^', domain='a.com', rule_type='block',
                 wildcard=False, sources={'s1'}),
            Rule(raw='@@||a.com^', domain='a.com', rule_type='allow',
                 wildcard=False, sources={'s2'}),
        ]
        out, _ = engine.deduplicate(iter(rules))
        assert len(out) == 2


# ═══════════════════════════════════════════════════════════════
#  Cache
# ═══════════════════════════════════════════════════════════════


class TestSourceCache:
    def test_write_read(self, tmp_path):
        sc = SourceCache(cache_dir=str(tmp_path / 'cache'), ttl=3600)
        sc.write('http://test.com', 'content123', etag='abc')
        assert sc.read('http://test.com') == 'content123'

    def test_freshness(self, tmp_path):
        sc = SourceCache(cache_dir=str(tmp_path / 'cache'), ttl=1)
        sc.write('http://test.com', 'data')
        assert sc.is_fresh('http://test.com')

    def test_stale(self, tmp_path):
        sc = SourceCache(cache_dir=str(tmp_path / 'cache'), ttl=0)
        sc.write('http://test.com', 'data')
        assert not sc.is_fresh('http://test.com')

    def test_conditional_headers(self, tmp_path):
        sc = SourceCache(cache_dir=str(tmp_path / 'cache'), ttl=3600)
        sc.write('http://test.com', 'data', etag='xyz', last_modified='Mon')
        headers = sc.get_headers('http://test.com')
        assert headers['If-None-Match'] == 'xyz'
        assert headers['If-Modified-Since'] == 'Mon'

    def test_clear(self, tmp_path):
        sc = SourceCache(cache_dir=str(tmp_path / 'cache'), ttl=3600)
        sc.write('http://a.com', 'data1')
        sc.write('http://b.com', 'data2')
        count = sc.clear()
        assert count == 2
        assert sc.read('http://a.com') is None

    def test_stats(self, tmp_path):
        sc = SourceCache(cache_dir=str(tmp_path / 'cache'), ttl=3600)
        sc.write('http://a.com', 'x' * 1000)
        s = sc.stats()
        assert s['entries'] == 1
        assert s['fresh'] == 1


# ═══════════════════════════════════════════════════════════════
#  Async engine
# ═══════════════════════════════════════════════════════════════


class TestAsyncEngine:
    def test_sync_wrapper(self):
        """Test that sync merge() works via asyncio.run()."""
        engine = RuleEngine(use_cache=False, timeout=10)
        # This would try to fetch real URLs, so we skip in unit tests
        # Just verify the engine initializes
        assert engine.parser is not None
        assert engine.cache is None

    def test_dedup_from_iterator(self):
        """Test that deduplicate() works with a generator."""
        engine = RuleEngine(use_cache=False)

        def gen():
            for i in range(5):
                yield Rule(raw=f'||a{i}.com^', domain=f'a{i}.com',
                           rule_type='block', wildcard=False, sources={'s1'})
            # Duplicate
            yield Rule(raw='||a0.com^', domain='a0.com', rule_type='block',
                       wildcard=False, sources={'s2'})

        out, report = engine.deduplicate(gen())
        assert len(out) == 5
        assert report.exact_merged == 1
        a0 = next(r for r in out if r.normalized_domain == 'a0.com')
        assert a0.sources == {'s1', 's2'}
