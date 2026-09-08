#!/usr/bin/env python3
"""V3 CLI for merging AdGuard rules — typer + rich powered.

Usage:
  python merge_rules.py --config config/sources.yaml
  python merge_rules.py -s URL1 URL2 -o output.txt --report
  python merge_rules.py --config config/sources.yaml --dry-run
  python merge_rules.py --init                    # generate default config
  python merge_rules.py --validate config/sources.yaml
  python merge_rules.py --cache-stats             # show cache statistics
  python merge_rules.py --cache-clear             # clear all cache
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from merger import (
    AsyncRuleEngine,
    MergeReporter,
    RuleNormalizer,
    SourceCache,
    __version__,
)
from config_loader import (
    generate_default_config,
    load_config,
    load_source_metas,
    validate_config,
)

app = typer.Typer(
    name="adguard-rules-merger",
    help="V3: Merge AdGuard filter rules with async I/O, streaming, and incremental cache.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


# ── logging setup ───────────────────────────────────────────────────


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )


# ── output writers ──────────────────────────────────────────────────


def write_output(rules, path: Path, stats: dict | None = None) -> None:
    """Write merged rules to file with metadata header."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("! Merged AdGuard Filter Rules (V3)\n")
        f.write(f"! Generated: {datetime.now(timezone.utc).isoformat()}\n")
        if stats:
            f.write(f"! Sources: {stats.get('sources_ok', 0)}/{stats.get('sources_total', 0)}")
            f.write(f" ({stats.get('sources_cached', 0)} cached)\n")
            f.write(f"! Total rules: {len(rules)}\n")
            f.write(f"! Dedup rate: {stats.get('dedup_rate', 0):.1f}%\n")
            f.write(f"! Dedup detail: exact_merged={stats.get('exact_merged', 0)}"
                    f" normalized_merged={stats.get('normalized_merged', 0)}"
                    f" wildcard_removed={stats.get('wildcard_removed', 0)}"
                    f" conflict_resolved={stats.get('conflict_resolved', 0)}\n")
        f.write("!\n")
        for rule in rules:
            f.write(f"{rule}\n")


def write_compressed(rules, path: Path, stats: dict | None = None) -> None:
    """Write gzip-compressed output."""
    uncompressed_path = path.with_suffix("")
    write_output(rules, uncompressed_path, stats)
    with open(uncompressed_path, "rb") as f_in:
        with gzip.open(path, "wb") as f_out:
            f_out.writelines(f_in)
    uncompressed_path.unlink()


def write_stats_json(stats: dict, rules, path: Path) -> None:
    """Write detailed stats.json."""
    from collections import Counter
    source_counts = Counter()
    category_counts = Counter()
    for r in rules:
        for s in r.sources:
            source_counts[s] += 1
        category_counts[r.category] += 1

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": stats,
        "per_source": dict(source_counts.most_common()),
        "per_category": dict(category_counts),
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# ── main merge command ──────────────────────────────────────────────


@app.command()
def merge(
    config: Optional[str] = typer.Option(
        None, "--config", "-c",
        help="YAML config file path",
    ),
    sources: Optional[List[str]] = typer.Option(
        None, "--sources", "-s",
        help="Source URLs (space-separated)",
    ),
    output: str = typer.Option(
        "output/merged_rules.txt", "--output", "-o",
        help="Output file path",
    ),
    report: bool = typer.Option(
        False, "--report", "-r",
        help="Generate merge report",
    ),
    report_format: str = typer.Option(
        "markdown", "--report-format",
        help="Report format: markdown, text, json",
    ),
    detect_conflicts: bool = typer.Option(
        False, "--detect-conflicts",
        help="Detect block/allow conflicts",
    ),
    no_allow_override: bool = typer.Option(
        False, "--no-allow-override",
        help="Disable allow-overrides-block resolution",
    ),
    normalized_dedup: bool = typer.Option(
        False, "--normalized-dedup",
        help="Enable fuzzy/normalized dedup (www-equivalence etc.)",
    ),
    strip_www: bool = typer.Option(
        False, "--strip-www",
        help="Treat www.example.com and example.com as equivalent",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Fetch + dedup but don't write output",
    ),
    compress: bool = typer.Option(
        False, "--compress",
        help="Also output .gz compressed version",
    ),
    timeout: int = typer.Option(60, "--timeout", help="Per-request timeout (seconds)"),
    max_concurrency: int = typer.Option(
        50, "--max-concurrency", "-w",
        help="Max concurrent HTTP requests",
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache",
        help="Disable incremental cache",
    ),
    cache_dir: str = typer.Option("cache", "--cache-dir", help="Cache directory"),
    cache_ttl: int = typer.Option(
        0, "--cache-ttl",
        help="Cache TTL in seconds (0 = no expiry)",
    ),
    cache_max_size: int = typer.Option(
        0, "--cache-max-size",
        help="Max cache size in MB (0 = unlimited)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet output"),
):
    """Merge AdGuard filter rules from multiple sources."""
    setup_logging(verbose, quiet)
    log = logging.getLogger("merge")

    # load sources
    source_metas = []
    if config:
        try:
            cfg = load_config(config)
            source_metas = load_source_metas(config)
            # apply config-level settings if not overridden by CLI
            if timeout == 60 and cfg.timeout != 60:
                timeout = cfg.timeout
            if max_concurrency == 50 and cfg.max_concurrency != 50:
                max_concurrency = cfg.max_concurrency
            if not no_allow_override and not cfg.allow_overrides_block:
                no_allow_override = True
            if not normalized_dedup and cfg.enable_normalized_dedup:
                normalized_dedup = True
            if not strip_www and cfg.strip_www:
                strip_www = True
            if not no_cache and not cfg.cache.enabled:
                no_cache = True
            if compress or cfg.output.compress:
                compress = True
            log.info("Loaded %d sources from %s", len(source_metas), config)
        except Exception as e:
            console.print(f"[red]Config error: {e}[/red]")
            raise typer.Exit(code=1)
    elif sources:
        from merger.models import SourceMeta
        source_metas = [SourceMeta(name=u, url=u) for u in sources]
    else:
        console.print("[red]Error: specify --config or --sources[/red]")
        raise typer.Exit(code=1)

    if not source_metas:
        console.print("[red]No enabled sources![/red]")
        raise typer.Exit(code=1)

    # build normalizer
    normalizer = RuleNormalizer(strip_www=strip_www) if (normalized_dedup or strip_www) else None

    # build engine
    cache_dir_arg = None if no_cache else cache_dir
    engine = AsyncRuleEngine(
        timeout=timeout,
        max_concurrency=max_concurrency,
        allow_overrides_block=not no_allow_override,
        cache_dir=cache_dir_arg,
        cache_ttl=cache_ttl,
        cache_max_size_mb=cache_max_size,
        enable_normalized_dedup=normalized_dedup,
        normalizer=normalizer,
    )

    console.print(f"\n[bold cyan]AdGuard Rules Merger v{__version__}[/bold cyan]")
    console.print(f"  Sources: {len(source_metas)} | Concurrency: {max_concurrency}")
    console.print(f"  Cache: {'disabled' if no_cache else f'{cache_dir} (TTL={cache_ttl}s)'}")
    if normalized_dedup:
        console.print(f"  Normalized dedup: enabled (strip_www={strip_www})")
    console.print()

    # run merge with progress
    t0 = time.time()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        fetch_task = progress.add_task("Fetching & parsing sources...", total=len(source_metas))

        # We can't easily show per-source progress with asyncio.gather,
        # so we run the merge and update the bar after completion.
        async def _run():
            async with engine:
                result = await engine.merge(
                    source_metas,
                    return_stats=True,
                    detect_conflicts=detect_conflicts,
                )
                progress.update(fetch_task, completed=len(source_metas))
                return result

        try:
            result = asyncio.run(_run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled[/yellow]")
            raise typer.Exit(code=1)
        except Exception as e:
            # Always print full traceback in CI/non-interactive mode
            console.print(f"\n[red bold]✗ Merge failed: {type(e).__name__}: {e}[/red bold]")
            console.print("\n[red]Full traceback:[/red]")
            import traceback
            traceback.print_exc()
            # Also log to file for debugging
            try:
                with open("merge_error.log", "w") as f:
                    f.write(f"Error: {type(e).__name__}: {e}\n\n")
                    traceback.print_exc(file=f)
                console.print(f"[dim]Error log written to merge_error.log[/dim]")
            except Exception:
                pass
            raise typer.Exit(code=1)

    rules = result["rules"]
    stats = result["stats"]
    elapsed = time.time() - t0

    # results table
    table = Table(title="Merge Results", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    table.add_row("Rules (before)", f"{stats['total_before']:,}")
    table.add_row("Rules (after)", f"{len(rules):,}")
    table.add_row("Dedup rate", f"{stats['dedup_rate']:.1f}%")
    table.add_row("Block / Allow / Comment",
                  f"{stats['block_count']:,} / {stats['allow_count']:,} / {stats['comment_count']:,}")
    table.add_row("Sources (ok/cached/total)",
                  f"{stats['sources_ok']} / {stats['sources_cached']} / {stats['sources_total']}")
    table.add_row("Exact merged", f"{stats['exact_merged']:,}")
    if stats.get('normalized_merged', 0) > 0:
        table.add_row("Normalized merged", f"{stats['normalized_merged']:,}")
    table.add_row("Wildcard removed", f"{stats['wildcard_removed']:,}")
    table.add_row("Conflicts resolved", f"{stats['conflict_resolved']:,}")
    table.add_row("Time", f"{elapsed:.2f}s")
    console.print(table)

    if detect_conflicts:
        conflicts = result.get("conflicts", [])
        if conflicts:
            console.print(f"\n[yellow]⚠ {len(conflicts)} block/allow conflicts detected:[/yellow]")
            for c in conflicts[:10]:
                console.print(f"  - {c['domain']}")
            if len(conflicts) > 10:
                console.print(f"  ... and {len(conflicts) - 10} more")

    # write output
    if dry_run:
        console.print("\n[yellow]Dry-run mode — skipping file write[/yellow]")
    else:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        write_output(rules, out, stats)
        console.print(f"\n[green]✓ Written to {out.absolute()}[/green]")

        if compress:
            gz_path = out.with_suffix(out.suffix + ".gz")
            write_compressed(rules, gz_path, stats)
            console.print(f"[green]✓ Compressed: {gz_path.absolute()}[/green]")

        # stats.json
        stats_path = out.parent / "stats.json"
        write_stats_json(stats, rules, stats_path)
        console.print(f"[green]✓ Stats: {stats_path.absolute()}[/green]")

    # report
    if report:
        reporter = MergeReporter(rules, stats)
        ext = {"markdown": "md", "text": "txt", "json": "json"}[report_format]
        rp = Path(output).with_suffix(f".report.{ext}")
        reporter.save(str(rp), fmt=report_format)
        console.print(f"[green]✓ Report: {rp.absolute()}[/green]")

    console.print()


# ── utility commands ─────────────────────────────────────────────────


@app.command()
def init(
    output: str = typer.Option("config/sources.yaml", "--output", "-o",
                                help="Output config path"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing file"),
):
    """Generate a default configuration file."""
    p = Path(output)
    if p.exists() and not force:
        console.print(f"[red]File already exists: {output} (use --force to overwrite)[/red]")
        raise typer.Exit(code=1)
    generate_default_config(output)
    console.print(f"[green]✓ Default config written to {p.absolute()}[/green]")


@app.command()
def validate(
    config: str = typer.Argument(..., help="Config file path to validate"),
):
    """Validate a configuration file."""
    issues = validate_config(config)
    if issues:
        console.print(f"[red]✗ {len(issues)} issue(s) found:[/red]")
        for i in issues:
            console.print(f"  - {i}")
        raise typer.Exit(code=1)
    else:
        cfg = load_config(config)
        console.print(f"[green]✓ Valid config[/green]")
        console.print(f"  Sources: {len(cfg.sources)} ({sum(1 for s in cfg.sources if s.enabled)} enabled)")
        console.print(f"  Cache: {'enabled' if cfg.cache.enabled else 'disabled'}")
        console.print(f"  Output dir: {cfg.output.directory}")


@app.command(name="cache-stats")
def cache_stats(
    cache_dir: str = typer.Option("cache", "--cache-dir", help="Cache directory"),
):
    """Show cache statistics."""
    cache = SourceCache(cache_dir=cache_dir)
    cache.load()
    stats = cache.stats()
    table = Table(title="Cache Statistics", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    table.add_row("Entries", f"{stats['entry_count']}")
    table.add_row("Total size", f"{stats['total_size_mb']} MB")
    table.add_row("TTL", f"{stats['ttl_seconds']}s" if stats['ttl_seconds'] > 0 else "no expiry")
    table.add_row("Max size", f"{stats['max_size_mb']} MB" if stats['max_size_mb'] > 0 else "unlimited")
    console.print(table)


@app.command(name="cache-clear")
def cache_clear(
    cache_dir: str = typer.Option("cache", "--cache-dir", help="Cache directory"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Clear all cached data."""
    if not yes:
        confirm = typer.confirm(f"Clear all cache in {cache_dir}?")
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit(code=0)
    cache = SourceCache(cache_dir=cache_dir)
    cache.load()
    cache.clear()
    console.print("[green]✓ Cache cleared[/green]")


@app.command()
def version():
    """Show version information."""
    console.print(f"AdGuard Rules Merger v{__version__}")


if __name__ == "__main__":
    app()
