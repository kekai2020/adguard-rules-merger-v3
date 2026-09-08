"""V3 Incremental cache — ETag / Last-Modified / content hash.

Stores cached responses on disk so repeated runs skip unchanged sources.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

CACHE_META = 'cache_meta.json'


class SourceCache:
    """Disk-backed HTTP response cache with ETag / Last-Modified support."""

    def __init__(self, cache_dir: str = '.cache/sources', ttl: int = 3600) -> None:
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self.meta_path = self.dir / CACHE_META
        self.meta: Dict[str, Any] = self._load_meta()

    def _load_meta(self) -> Dict[str, Any]:
        if self.meta_path.exists():
            try:
                return json.loads(self.meta_path.read_text(encoding='utf-8'))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_meta(self) -> None:
        self.meta_path.write_text(
            json.dumps(self.meta, indent=2, ensure_ascii=False),
            encoding='utf-8',
        )

    @staticmethod
    def _url_key(url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()[:16]

    def _content_path(self, url: str) -> Path:
        return self.dir / f'{self._url_key(url)}.txt'

    def get_headers(self, url: str) -> Dict[str, str]:
        """Return conditional request headers for a URL."""
        entry = self.meta.get(url, {})
        headers: Dict[str, str] = {}
        if etag := entry.get('etag'):
            headers['If-None-Match'] = etag
        if lm := entry.get('last_modified'):
            headers['If-Modified-Since'] = lm
        return headers

    def is_fresh(self, url: str) -> bool:
        """Check if cached content exists and is within TTL."""
        entry = self.meta.get(url, {})
        if not entry:
            return False
        ts = entry.get('timestamp', 0)
        if time.time() - ts > self.ttl:
            return False
        cp = self._content_path(url)
        return cp.exists()

    def read(self, url: str) -> Optional[str]:
        """Read cached content if fresh."""
        if not self.is_fresh(url):
            return None
        cp = self._content_path(url)
        try:
            return cp.read_text(encoding='utf-8')
        except OSError:
            return None

    def write(self, url: str, content: str,
              etag: str = '', last_modified: str = '') -> None:
        """Store content and response headers."""
        cp = self._content_path(url)
        cp.write_text(content, encoding='utf-8')
        self.meta[url] = {
            'etag': etag,
            'last_modified': last_modified,
            'timestamp': time.time(),
            'size': len(content),
            'hash': hashlib.sha256(content.encode()).hexdigest()[:16],
        }
        self._save_meta()
        logger.debug('Cached %s (%d bytes)', url, len(content))

    def update_headers(self, url: str, etag: str = '', last_modified: str = '') -> None:
        """Update only headers (for 304 responses)."""
        entry = self.meta.get(url, {})
        if etag:
            entry['etag'] = etag
        if last_modified:
            entry['last_modified'] = last_modified
        entry['timestamp'] = time.time()
        self.meta[url] = entry
        self._save_meta()

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        total_size = 0
        fresh = 0
        for url, entry in self.meta.items():
            total_size += entry.get('size', 0)
            if time.time() - entry.get('timestamp', 0) < self.ttl:
                fresh += 1
        return {
            'entries': len(self.meta),
            'fresh': fresh,
            'total_size_mb': round(total_size / 1024 / 1024, 1),
        }

    def clear(self) -> int:
        """Remove all cached files. Returns count removed."""
        count = 0
        for f in self.dir.glob('*.txt'):
            f.unlink()
            count += 1
        self.meta = {}
        self._save_meta()
        return count
