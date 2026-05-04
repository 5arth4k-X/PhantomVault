"""
PhantomVault — utils/aliases.py
Maps vault alias names to container file paths.
Stored in a simple JSON file. Not sensitive — paths are not secrets,
but the file location is kept in the user's home directory.
"""

import json
import os
from pathlib import Path
from typing import Optional


def _alias_file() -> Path:
    """Returns the path to the alias store file."""
    base = Path.home() / ".phantomvault"
    base.mkdir(mode=0o700, exist_ok=True)
    return base / "vaults.json"


def _load() -> dict:
    """Loads the alias store. Returns empty dict if file does not exist."""
    f = _alias_file()
    if not f.exists():
        return {}
    try:
        with open(f, "r") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    """Saves the alias store atomically."""
    f = _alias_file()
    tmp = f.with_suffix(".tmp")
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
    tmp.replace(f)


def register(alias: str, container_path: str) -> None:
    """Register a vault alias pointing to a container file path."""
    data = _load()
    data[alias] = str(container_path)
    _save(data)


def resolve(alias: str) -> Optional[str]:
    """Resolve an alias to its container path. Returns None if not found."""
    return _load().get(alias)


def remove(alias: str) -> bool:
    """Remove an alias. Returns True if it existed."""
    data = _load()
    if alias not in data:
        return False
    del data[alias]
    _save(data)
    return True


def list_all() -> dict:
    """Return all alias -> path mappings."""
    return _load()


def alias_exists(alias: str) -> bool:
    """Returns True if the alias is registered."""
    return alias in _load()
