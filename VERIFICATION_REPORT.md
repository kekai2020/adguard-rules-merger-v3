# AdGuard Rules Merger V2 — Verification Report

**Date:** 2026-09-08
**Version:** 2.0.0

---

## 1. Original V1 Verification (2026-09-07)

对 sources.yaml 中 14 个启用源独立下载并与 merged_rules.txt 对比：

| 指标 | 数值 |
|------|------|
| Block 覆盖率 | 99.9976% |
| Allow 覆盖率 | 100.0000% |
| 真正缺失 | 0 条 |

74 条"缺失"规则全部被通配符智能去重正确移除。合并逻辑正确。

---

## 2. V1 → V2 Changes

### Critical Bug Fixes

| Bug | V1 | V2 Fix |
|-----|-----|--------|
| `__eq__` / `__hash__` inconsistent | `__hash__` used `(norm, type)` but dedup used different key | Both use `(norm, type, wildcard)` — consistent |
| `DomainTrie.is_covered` off-by-one | Wildcard check after descending | Check `__wc__` BEFORE descending — correct semantics |
| Source loss on dedup | Sources not merged when duplicates found | `existing.sources \|= new.sources` — all sources preserved |
| Hosts regex `$` anchor | `# comment` at end of hosts line broke parsing | Removed `$` — allows inline comments |
| No conflict resolution | Both block+allow kept | Phase 3: allow-overrides-block (configurable) |
| `*.a.com` vs `a.com` collision | Same dedup key → wildcard swallowed exact | Different keys: `(a.com, block, True)` ≠ `(a.com, block, False)` |

### New Features

- **DedupReport**: Tracks exact_merged / wildcard_removed / conflict_resolved counts
- **Per-source attribution**: Each Rule stores `sources: Set[str]` with all contributing sources
- **Allow-overrides-block**: Phase 3 conflict resolution (AdGuard semantics)
- **`--verify` flag**: CLI can verify output against sources after merge
- **`--dry-run` flag**: Fetch + dedup without writing output
- **`validate_config()`**: Config validation utility
- **65 unit tests**: Covering all edge cases

### Dedup Algorithm (V2)

```
Phase 1 — Exact dedup:
  Key = (normalized_domain, rule_type, wildcard)
  On collision: merge source sets, keep one rule.
  *.a.com and a.com are separate keys.

Phase 2 — Wildcard coverage:
  Build DomainTrie from all wildcard domains.
  Remove non-wildcard rules that are strict subdomains.
  (*.a.com removes ads.a.com but NOT a.com)

Phase 3 — Allow-overrides-block (optional):
  If same domain has both block + allow → keep allow.
  Merge block sources into allow rule.
```

---

## 3. Test Results

```
65 passed in 0.29s

TestRuleModel:     20 tests (equality, normalization, domain relationships)
TestParser:        19 tests (all formats, edge cases)
TestDomainTrie:     7 tests (coverage, self-not-covered, deep wildcards)
TestEngineDedup:   13 tests (exact, wildcard, source merging)
TestConflictResolution: 3 tests
TestEndToEnd:       3 tests (combined scenarios)
```

---

## 4. File Structure (V2)

```
adguard-rules-merger/
├── merger/
│   ├── __init__.py        v2.0.0
│   ├── core.py            RuleEngine + DomainTrie + DedupReport
│   ├── models.py          Rule (consistent __eq__/__hash__, source tracking)
│   ├── parser.py          RuleParser (all formats, IPv6, hosts comments)
│   └── reporter.py        MergeReporter (per-source attribution)
├── config/sources.yaml    (unchanged)
├── tests/test_core.py     65 tests ✅
├── .github/workflows/merge.yml  (v2 stats in commit)
├── merge_rules.py         CLI (--verify, --dry-run, --no-allow-override)
├── config_loader.py       (validation utility)
├── validate_output.py     (standalone verification)
├── requirements.txt
├── pytest.ini
└── VERIFICATION_REPORT.md
```
