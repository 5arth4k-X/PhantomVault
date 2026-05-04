"""
PhantomVault — stealth.py
Ghost directory management.

When a vault is locked:
- Files in the source directory are moved to the encrypted container
- Source directory is left empty
- Container mtime is randomised

When unlocked:
- Decrypted files are written to the source directory

IMPORTANT: Filesystem journal analysis (extundelete, Autopsy) may
recover directory history even after files are removed.
For maximum stealth, create vaults on freshly formatted volumes.
This limitation is documented in docs/SECURITY.md.
"""

import os
import shutil
import stat
import time
import random
from pathlib import Path
from typing import List, Tuple


def collect_files(directory: str) -> List[Tuple[str, str]]:
    """
    Collects all files in a directory recursively.
    Returns list of (absolute_path, relative_path) tuples.
    Relative path is used to reconstruct directory structure in vault.
    """
    source = Path(directory)
    if not source.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    files = []
    for item in source.rglob("*"):
        if item.is_file():
            rel = str(item.relative_to(source))
            files.append((str(item), rel))
    return files


def secure_delete_file(path: str) -> None:
    """
    Securely deletes a file by overwriting with random data before deletion.
    Reduces (but does not eliminate) forensic recovery from disk.
    Filesystem journal may still record the file's existence.
    """
    p = Path(path)
    if not p.exists():
        return

    try:
        size = p.stat().st_size
        if size > 0:
            with open(p, "r+b") as f:
                # Overwrite with random data
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
    except OSError:
        pass

    # Rename to random name before deletion (reduces journal trace)
    random_name = p.parent / _random_name()
    try:
        p.rename(random_name)
        random_name.unlink()
    except OSError:
        try:
            p.unlink()
        except OSError:
            pass


def clear_directory(directory: str) -> None:
    """
    Securely removes all files from a directory, leaving it empty.
    Uses random rename chains to obscure original filenames in journal.
    """
    source = Path(directory)
    if not source.exists():
        return

    for item in list(source.rglob("*")):
        if item.is_file():
            secure_delete_file(str(item))

    # Remove empty subdirectories
    for item in sorted(source.rglob("*"), reverse=True):
        if item.is_dir():
            try:
                item.rmdir()
            except OSError:
                pass


def restore_files(
    directory: str,
    files: List[Tuple[str, bytes]],
) -> None:
    """
    Writes decrypted files back to the source directory.

    Args:
        directory: The source directory path.
        files: List of (relative_path, file_bytes) tuples.
    """
    source = Path(directory)
    source.mkdir(parents=True, exist_ok=True)

    for rel_path, data in files:
        target = source / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as f:
            f.write(data)


def randomise_mtime(container_path: str) -> None:
    """
    Sets the container file's modification time to a random value
    within 72 hours of the current time.
    Obscures when the vault was actually last accessed.
    """
    now = time.time()
    delta = random.uniform(-72 * 3600, 72 * 3600)
    fake_time = now + delta
    try:
        os.utime(container_path, (fake_time, fake_time))
    except OSError:
        pass


def _random_name() -> str:
    """Generates a random filename for rename chain."""
    return f".tmp_{os.urandom(8).hex()}"
