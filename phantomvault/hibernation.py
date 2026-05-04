"""
PhantomVault — hibernation.py
Checks if system hibernation is enabled at startup.
If enabled, displays a warning — keys may be written to disk
during a hibernate event even if mlock is active.
"""

import os
import platform
import subprocess
from pathlib import Path


def check_and_warn() -> bool:
    """
    Checks if hibernation is enabled on the current platform.
    Displays a warning if it is.
    Returns True if hibernation is enabled (warning shown).
    """
    system = platform.system()

    if system == "Linux":
        return _check_linux()
    elif system == "Darwin":
        return _check_macos()
    elif system == "Windows":
        return _check_windows()
    return False


def _check_linux() -> bool:
    """Check Linux hibernation via /sys/power/disk."""
    disk_file = Path("/sys/power/disk")
    if not disk_file.exists():
        return False

    try:
        content = disk_file.read_text().strip()
        # Format: "platform [shutdown] suspend ..."
        # The active mode is in brackets.
        if "[" not in content:
            return False
        active = content[content.index("[") + 1: content.index("]")]
        if active not in ("platform", "shutdown", "reboot"):
            return False

        _display_warning()
        return True
    except OSError:
        return False


def _check_macos() -> bool:
    """Check macOS hibernation via pmset."""
    try:
        result = subprocess.run(
            ["pmset", "-g"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if "hibernatemode" in line:
                parts = line.split()
                if len(parts) >= 2:
                    mode = int(parts[-1])
                    if mode != 0:
                        _display_warning()
                        return True
    except (subprocess.SubprocessError, ValueError, OSError):
        pass
    return False


def _check_windows() -> bool:
    """Check Windows hibernation via hiberfil.sys existence."""
    hiberfil = Path("C:/hiberfil.sys")
    if hiberfil.exists():
        _display_warning()
        return True
    return False


def _display_warning() -> None:
    from phantomvault.utils.warnings import warn_hibernation_enabled
    warn_hibernation_enabled(platform.system())
