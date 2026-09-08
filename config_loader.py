"""V3 Configuration loader — pydantic-based validation with JSON Schema.

Enhancements over V2:
  - pydantic v2 models for type-safe config loading
  - Automatic validation with friendly error messages
  - Source reputation scores for quality scoring (Phase 2)
  - Per-source category tags for tiered output
  - Cache configuration section
  - Output configuration section (multi-format, compression)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


# ── pydantic models ─────────────────────────────────────────────────


class SourceConfig(BaseModel):
    """Configuration for a single rule source."""

    name: str
    url: str
    enabled: bool = True
    category: str = "other"
    reputation: float = Field(default=0.5, ge=0.0, le=1.0)
    timeout: Optional[int] = Field(default=None, ge=1)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        # allow local file paths
        if v.startswith(("http://", "https://", "file://")):
            return v
        # local file path
        p = Path(v)
        if p.exists() and p.is_file():
            return v
        # assume it's a URL even without scheme (will fail at fetch time if invalid)
        return v


class CacheConfig(BaseModel):
    """Incremental cache configuration."""

    enabled: bool = True
    directory: str = "cache"
    ttl_seconds: int = Field(default=0, ge=0, description="0 = no time-based expiry")
    max_size_mb: int = Field(default=0, ge=0, description="0 = unlimited")


class OutputConfig(BaseModel):
    """Output configuration."""

    directory: str = "output"
    filename: str = "merged_rules.txt"
    formats: List[str] = Field(default_factory=lambda: ["adguard"])
    compress: bool = False
    include_stats: bool = True
    include_report: bool = True


class MergeConfig(BaseModel):
    """Top-level merge configuration."""

    sources: List[SourceConfig] = Field(default_factory=list)
    test_sources: List[SourceConfig] = Field(default_factory=list)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    # merge behavior
    timeout: int = Field(default=60, ge=1)
    max_concurrency: int = Field(default=50, ge=1, le=200)
    allow_overrides_block: bool = True
    enable_normalized_dedup: bool = False
    strip_www: bool = False

    @model_validator(mode="after")
    def check_sources(self) -> "MergeConfig":
        enabled = [s for s in self.sources if s.enabled]
        if not enabled:
            raise ValueError("At least one enabled source is required")
        # check for duplicate URLs
        urls = [s.url for s in enabled]
        if len(urls) != len(set(urls)):
            seen = set()
            dupes = []
            for u in urls:
                if u in seen:
                    dupes.append(u)
                seen.add(u)
            raise ValueError(f"Duplicate source URLs: {dupes}")
        return self


# ── loader functions ─────────────────────────────────────────────────


def load_config(config_path: str = "config/sources.yaml") -> MergeConfig:
    """Load and validate configuration from a YAML file.

    Args:
        config_path: Path to the YAML config file.

    Returns:
        Validated MergeConfig instance.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        ValueError: If config is invalid (with friendly error messages).
    """
    p = Path(config_path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    with open(p, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raise ValueError(f"Config file is empty: {config_path}")

    try:
        return MergeConfig(**raw)
    except Exception as e:
        # re-raise with context
        raise ValueError(f"Config validation failed: {e}") from e


def load_sources(config_path: str = "config/sources.yaml") -> List[Dict[str, Any]]:
    """Return list of enabled source dicts (V2-compatible)."""
    cfg = load_config(config_path)
    return [
        {
            "name": s.name,
            "url": s.url,
            "category": s.category,
            "reputation": s.reputation,
            "enabled": s.enabled,
        }
        for s in cfg.sources
        if s.enabled
    ]


def load_source_metas(config_path: str = "config/sources.yaml") -> List:
    """Return list of SourceMeta objects for the engine."""
    from .models import SourceMeta  # local import to avoid circular
    cfg = load_config(config_path)
    return [
        SourceMeta(
            name=s.name,
            url=s.url,
            category=s.category,
            enabled=s.enabled,
            reputation=s.reputation,
            timeout=s.timeout,
        )
        for s in cfg.sources
        if s.enabled
    ]


def validate_config(config_path: str = "config/sources.yaml") -> List[str]:
    """Validate config and return list of issues (empty = valid)."""
    try:
        load_config(config_path)
        return []
    except (FileNotFoundError, ValueError) as e:
        return [str(e)]


def generate_json_schema(output_path: str = "config/schema.json") -> None:
    """Generate JSON Schema for the config file."""
    schema = MergeConfig.model_json_schema()
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(schema, indent=2, ensure_ascii=False), encoding="utf-8")


def generate_default_config(output_path: str = "config/sources.yaml") -> None:
    """Generate a default config file with example sources."""
    default = {
        "sources": [
            {
                "name": "AdGuard DNS filter",
                "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
                "enabled": True,
                "category": "ads",
                "reputation": 0.95,
            },
            {
                "name": "1Hosts (Lite)",
                "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt",
                "enabled": True,
                "category": "ads",
                "reputation": 0.85,
            },
        ],
        "cache": {
            "enabled": True,
            "directory": "cache",
            "ttl_seconds": 0,
            "max_size_mb": 500,
        },
        "output": {
            "directory": "output",
            "filename": "merged_rules.txt",
            "formats": ["adguard"],
            "compress": False,
            "include_stats": True,
            "include_report": True,
        },
        "timeout": 60,
        "max_concurrency": 50,
        "allow_overrides_block": True,
        "enable_normalized_dedup": False,
        "strip_www": False,
    }
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.dump(default, default_flow_style=False, allow_unicode=True), encoding="utf-8")


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "config/sources.yaml"
    issues = validate_config(path)
    if issues:
        print("Issues found:")
        for i in issues:
            print(f"  - {i}")
        sys.exit(1)
    else:
        cfg = load_config(path)
        print(f"Valid config with {len(cfg.sources)} sources "
              f"({sum(1 for s in cfg.sources if s.enabled)} enabled):")
        for s in cfg.sources:
            status = "✓" if s.enabled else "✗"
            print(f"  [{status}] [{s.category}] {s.name} (reputation={s.reputation})")
