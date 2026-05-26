"""
PhantomVault — utils/aliases.py
Maps vault alias names to container file paths and metadata.
Stored as JSON in ~/.phantomvault/vaults.json.
"""

import json
import os
from pathlib import Path
from typing import Optional


def _alias_file() -> Path:
    base = Path.home() / ".phantomvault"
    base.mkdir(mode=0o700, exist_ok=True)
    return base / "vaults.json"


def _load() -> dict:
    f = _alias_file()
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    f = _alias_file()
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(f)


def register(
    alias: str,
    container_path: str,
    source_path: str = "",
    region_offset: int = 0,
    region_len: int = 0,
) -> None:
    """Register a vault alias with all metadata needed for unlock."""
    data = _load()
    data[alias] = {
        "container": str(container_path),
        "source": str(source_path),
        "region_offset": region_offset,
        "region_len": region_len,
    }
    _save(data)


def resolve(alias: str) -> Optional[str]:
    """Resolve alias to container path. Returns None if not found."""
    entry = _load().get(alias)
    if entry is None:
        return None
    if isinstance(entry, dict):
        return entry.get("container")
    return str(entry)  # backward compat with old string-only format


def resolve_full(alias: str) -> Optional[dict]:
    """Resolve alias to full metadata dict."""
    entry = _load().get(alias)
    if entry is None:
        return None
    if isinstance(entry, dict):
        return entry
    # Backward compat: old format was just a string path
    return {"container": str(entry), "source": "", "region_offset": 0, "region_len": 0}


def update_region(alias: str, region_offset: int, region_len: int) -> None:
    """Update the stored region offset and length after writing encrypted data."""
    data = _load()
    if alias in data and isinstance(data[alias], dict):
        data[alias]["region_offset"] = region_offset
        data[alias]["region_len"] = region_len
        _save(data)


def mark_open(alias: str) -> None:
    """Mark a vault as currently open (survives across process restarts)."""
    data = _load()
    if alias in data and isinstance(data[alias], dict):
        data[alias]["open"] = True
        _save(data)


def mark_locked(alias: str) -> None:
    """Mark a vault as locked."""
    data = _load()
    if alias in data and isinstance(data[alias], dict):
        data[alias]["open"] = False
        _save(data)


def is_open(alias: str) -> bool:
    """Returns True if the vault is currently marked as open."""
    entry = _load().get(alias)
    if isinstance(entry, dict):
        return bool(entry.get("open", False))
    return False


def remove(alias: str) -> bool:
    data = _load()
    if alias not in data:
        return False
    del data[alias]
    _save(data)
    return True


def list_all() -> dict:
    return _load()


def alias_exists(alias: str) -> bool:
    return alias in _load()
