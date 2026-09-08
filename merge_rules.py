#!/usr/bin/env python3
"""V3 CLI — async merge with rich progress and typer interface."""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from merger import RuleEngine, MergeReporter
from config_loader import load_sources_config

app = typer.Typer(help='V3: Merge AdGuard filter rules with async IO and streaming dedup')
console = Console()


def write_output(rules, path: Path, stats: dict) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write('! Merged AdGuard Filter Rules\n')
        f.write(f'! Generated: {datetime.now(timezone.utc).isoformat()}\n')
        f.write(f'! Sources: {stats.get("sources_ok", 0)}/{stats.get("sources_total", 0)}\n')
        f.write(f'! Total rules: {len(rules)}\n')
        f.write(f'! Dedup rate: {stats.get("dedup_rate", 0):.1f}%\n')
        f.write(f'! Cache hits: {stats.get("cache_hits", 0)}\n')
        f.write('!\n')
        for rule in rules:
            f.write(f'{rule}\n')


@app.command()
def merge(
    config: str = typer.Option('config/sources.yaml', '--config', '-c', help='YAML config path'),
    output: str = typer.Option('merged_rules.txt', '--output', '-o', help='Output path'),
    report: bool = typer.Option(False, '--report', '-r', help='Generate report'),
    verify: bool = typer.Option(False, '--verify', help='Verify output after merge'),
    detect_conflicts: bool = typer.Option(False, '--detect-conflicts', help='Detect block/allow conflicts'),
    no_cache: bool = typer.Option(False, '--no-cache', help='Disable ETag cache'),
    cache_ttl: int = typer.Option(3600, '--cache-ttl', help='Cache TTL in seconds'),
    timeout: int = typer.Option(60, '--timeout', help='HTTP timeout'),
    max_workers: int = typer.Option(20, '--max-workers', help='Max concurrent fetches'),
):
    """Merge AdGuard filter rules from multiple sources."""
    try:
        sources = load_sources_config(config)
    except Exception as e:
        console.print(f'[red]Config error: {e}[/red]')
        raise typer.Exit(1)

    if not sources:
        console.print('[red]No sources![/red]')
        raise typer.Exit(1)

    console.print(f'[bold]AdGuard Rules Merger v3.0[/bold] — {len(sources)} sources')

    engine = RuleEngine(
        timeout=timeout,
        max_workers=max_workers,
        use_cache=not no_cache,
        cache_ttl=cache_ttl,
    )

    # Progress tracking
    progress = Progress(
        SpinnerColumn(),
        TextColumn('[progress.description]{task.description}'),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )

    completed = {'n': 0}
    cache_hits = {'n': 0}

    def progress_cb(url: str, from_cache: bool):
        completed['n'] += 1
        if from_cache:
            cache_hits['n'] += 1
        label = url.split('/')[-1][:40]
        task_progress.update(task, completed=completed['n'],
                            description=f'Fetching {label}')

    with progress:
        task = progress.add_task('Fetching sources...', total=len(sources))
        result = asyncio.run(engine.async_merge(
            sources,
            return_stats=True,
            detect_conflicts=detect_conflicts,
            progress_cb=progress_cb,
        ))

    rules = result['rules']
    stats = result['stats']

    # Write output
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_output(rules, out, stats)

    # Report
    if report:
        reporter = MergeReporter(rules, stats)
        rp = out.with_suffix('.report.md')
        reporter.save(str(rp), fmt='markdown')
        console.print(f'  Report: [cyan]{rp}[/cyan]')

    # Verify
    if verify:
        console.print('[yellow]Verifying...[/yellow]')
        from validate_output import validate_merged_output
        ok = validate_merged_output(sources, merged_rules=rules,
                                     timeout=timeout, workers=max_workers)
        if not ok:
            console.print('[red]Verification FAILED[/red]')
            raise typer.Exit(2)
        console.print('[green]Verification PASSED[/green]')

    # Summary table
    table = Table(title='V3 Merge Results', show_header=False)
    table.add_column('Metric', style='bold')
    table.add_column('Value', justify='right')
    table.add_row('Rules', f'{len(rules):,}')
    table.add_row('Block', f'{stats["block_count"]:,}')
    table.add_row('Allow', f'{stats["allow_count"]:,}')
    table.add_row('Comment', f'{stats["comment_count"]:,}')
    table.add_row('Dedup rate', f'{stats["dedup_rate"]:.1f}%')
    table.add_row('Exact merges', f'{stats["exact_merged"]:,}')
    table.add_row('Wildcard removed', f'{stats["wildcard_removed"]:,}')
    table.add_row('Conflicts resolved', f'{stats["conflict_resolved"]:,}')
    table.add_row('Cache hits', f'{stats["cache_hits"]}')
    table.add_row('Time', f'{stats["elapsed_time"]:.2f}s')
    table.add_row('Output', str(out.absolute()))
    console.print(table)


@app.command()
def cache_stats():
    """Show cache statistics."""
    from merger import SourceCache
    sc = SourceCache()
    s = sc.stats()
    console.print(f'Cache entries: {s["entries"]}')
    console.print(f'Fresh: {s["fresh"]}')
    console.print(f'Total size: {s["total_size_mb"]} MB')


@app.command()
def cache_clear():
    """Clear all cached sources."""
    from merger import SourceCache
    sc = SourceCache()
    count = sc.clear()
    console.print(f'Cleared {count} cached files')


if __name__ == '__main__':
    app()
