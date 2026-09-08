#!/usr/bin/env python3
"""V2 Validation tool — verifies merged output covers all source rules.

Usage:
  python validate_output.py --config config/sources.yaml
  python validate_output.py --config config/sources.yaml --merged output/merged_rules.txt
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

import requests
import yaml

# ── patterns ───────────────────────────────────────────────────

RE_BLOCK  = re.compile(r"^\|\|([^/^\s]+)\^")
RE_ALLOW  = re.compile(r"^@@\|\|([^/^\s]+)\^")
RE_COMMENT = re.compile(r"^!")
RE_HOSTS  = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)")
RE_PLAIN  = re.compile(r"^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")


def _norm(d: str) -> str:
    d = d.lower().strip()
    if d.startswith("*."):
        d = d[2:]
    if d.endswith("."):
        d = d[:-1]
    return d


def extract_domains(text: str) -> Tuple[Set[str], Set[str]]:
    """Return (block_domains, allow_domains) — all normalized."""
    block: Set[str] = set()
    allow: Set[str] = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or RE_COMMENT.match(s):
            continue
        m = RE_ALLOW.match(s)
        if m:
            allow.add(_norm(m.group(1)))
            continue
        m = RE_BLOCK.match(s)
        if m:
            block.add(_norm(m.group(1)))
            continue
        m = RE_HOSTS.match(s)
        if m:
            d = _norm(m.group(1))
            if d not in ("localhost", "localhost.localdomain"):
                block.add(d)
            continue
        if RE_PLAIN.match(s):
            block.add(_norm(s))
    return block, allow


def build_wildcard_parents(domains: Set[str]) -> Set[str]:
    """Build set of all ancestor domains that would be wildcard-covered."""
    parents: Set[str] = set()
    for d in domains:
        parts = d.split(".")
        for i in range(1, len(parts)):
            parents.add(".".join(parts[i:]))
    return parents


def is_wildcard_covered(domain: str, parents: Set[str]) -> bool:
    """Check if domain is a strict subdomain of any wildcard parent."""
    parts = domain.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in parents:
            return True
    return False


def download(url: str, timeout: int = 180) -> Optional[str]:
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"  ❌ {url}: {e}", file=sys.stderr)
        return None


def validate_merged_output(
    sources: List[str],
    merged_rules=None,
    merged_path: str = "output/merged_rules.txt",
    timeout: int = 180,
    workers: int = 5,
) -> bool:
    """Validate that merged output covers all source rules.

    Returns True if validation passes.
    """
    print("=" * 60)
    print("V2 Merged Output Validation")
    print("=" * 60)

    # load merged domains
    if merged_rules is not None:
        m_block = {r.normalized_domain for r in merged_rules if r.rule_type == "block"}
        m_allow = {r.normalized_domain for r in merged_rules if r.rule_type == "allow"}
    else:
        print(f"\n[1] Loading {merged_path}...")
        try:
            text = open(merged_path, encoding="utf-8").read()
        except FileNotFoundError:
            print(f"  Not found: {merged_path}")
            return False
        m_block, m_allow = extract_domains(text)

    print(f"  Merged block: {len(m_block):,}  allow: {len(m_allow):,}")

    # download sources
    print(f"\n[2] Downloading {len(sources)} sources...")
    src_data: Dict[str, Tuple[Set[str], Set[str]]] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(download, u, timeout): u for u in sources}
        for fut in as_completed(futs):
            url = futs[fut]
            text = fut.result()
            if text:
                b, a = extract_domains(text)
                src_data[url] = (b, a)
                print(f"  ✅ {len(b):,} block  {len(a):,} allow")

    # wildcard coverage from merged
    wc_parents = build_wildcard_parents(m_block | m_allow)

    # validate per source
    print(f"\n[3] Checking coverage...")
    total_truly_missing = 0
    all_ok = True

    for url, (s_block, s_allow) in src_data.items():
        miss_b = s_block - m_block
        miss_a = s_allow - m_allow

        truly_b = {d for d in miss_b if not is_wildcard_covered(d, wc_parents)}
        truly_a = {d for d in miss_a if not is_wildcard_covered(d, wc_parents)}
        total_truly_missing += len(truly_b) + len(truly_a)

        label = url.split("/")[-1][:50]
        if truly_b or truly_a:
            all_ok = False
            print(f"  ❌ {label}: {len(truly_b)} block + {len(truly_a)} allow MISSING")
            for d in sorted(truly_b)[:5]:
                print(f"     miss block: {d}")
            for d in sorted(truly_a)[:3]:
                print(f"     miss allow: {d}")
        else:
            wc_note = " (wildcard)" if miss_b or miss_a else ""
            print(f"  ✅ {label}{wc_note}")

    # summary
    print(f"\n{'=' * 60}")
    if all_ok:
        print("✅ Validation PASSED — all source rules covered")
    else:
        print(f"❌ Validation FAILED — {total_truly_missing} rules truly missing")

    return all_ok


def main() -> None:
    ap = argparse.ArgumentParser(description="V2: Validate merged AdGuard rules")
    ap.add_argument("-c", "--config", default="config/sources.yaml")
    ap.add_argument("-m", "--merged", default="output/merged_rules.txt")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--workers", type=int, default=5)
    args = ap.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    sources = [s["url"] for s in cfg.get("sources", []) if s.get("enabled", True)]

    if not sources:
        print("No enabled sources!")
        sys.exit(1)

    ok = validate_merged_output(sources, merged_path=args.merged,
                                timeout=args.timeout, workers=args.workers)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
