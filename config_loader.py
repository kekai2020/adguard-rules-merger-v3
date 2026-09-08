"""V3 Configuration loader with validation."""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List
import yaml


def _load_yaml(config_path: str) -> Dict[str, Any]:
    p = Path(config_path)
    if not p.exists():
        raise FileNotFoundError(f'Config not found: {config_path}')
    with open(p, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def load_sources_config(config_path: str = 'config/sources.yaml') -> List[str]:
    cfg = _load_yaml(config_path)
    return [s['url'] for s in cfg.get('sources', []) if s.get('enabled', True)]


def load_sources_with_names(config_path: str = 'config/sources.yaml') -> List[Dict[str, str]]:
    cfg = _load_yaml(config_path)
    return [
        {'name': s.get('name', 'unknown'), 'url': s['url'], 'category': s.get('category', '')}
        for s in cfg.get('sources', []) if s.get('enabled', True)
    ]


def validate_config(config_path: str = 'config/sources.yaml') -> List[str]:
    issues: List[str] = []
    try:
        cfg = _load_yaml(config_path)
    except Exception as e:
        return [f'Cannot load: {e}']
    if 'sources' not in cfg:
        return ['No sources key']
    urls = set()
    for i, s in enumerate(cfg['sources']):
        prefix = f'sources[{i}]'
        if 'url' not in s:
            issues.append(f'{prefix}: missing url')
            continue
        if s['url'] in urls:
            issues.append(f'{prefix}: duplicate url')
        urls.add(s['url'])
        if not s.get('name'):
            issues.append(f'{prefix}: missing name')
    return issues
