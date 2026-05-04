"""
PhantomVault — modes.py
Manages the security mode displayed at startup and feature availability.

Modes:
  SECURE   — Rust AES-256-GCM-SIV portable container (v1.0 default)
  KERNEL   — Linux LUKS kernel-level container (v2.0)
  PORTABLE — fallback mode (same as SECURE in v1.0)
"""

import platform
import os
from enum import Enum


class SecurityMode(Enum):
    SECURE = "SECURE"
    KERNEL = "KERNEL"
    PORTABLE = "PORTABLE"


def detect_mode() -> SecurityMode:
    """
    Detects the best available security mode for this platform.
    v1.0: always returns SECURE (Rust portable container).
    v2.0: will detect LUKS on Linux, BitLocker on Windows, etc.
    """
    # v1.0: SECURE mode on all platforms.
    return SecurityMode.SECURE


def get_mode_description(mode: SecurityMode) -> str:
    descriptions = {
        SecurityMode.SECURE: (
            "SECURE — Rust AES-256-GCM-SIV portable container. "
            "No root required. Works on all platforms."
        ),
        SecurityMode.KERNEL: (
            "KERNEL — Linux LUKS kernel-level encryption. "
            "Strongest mode. Requires root."
        ),
        SecurityMode.PORTABLE: (
            "PORTABLE — Software AES-256-GCM-SIV container. "
            "Cross-platform, no root required."
        ),
    }
    return descriptions.get(mode, "Unknown mode")
