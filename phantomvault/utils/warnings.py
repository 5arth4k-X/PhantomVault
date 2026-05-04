"""
PhantomVault — utils/warnings.py
Displays security warnings to the user. Never touches key material.
"""

import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

console = Console(stderr=True)


def warn_mlock_failed(message: str) -> None:
    """Display a warning when memory locking fails."""
    console.print(Panel(
        f"[yellow]Memory locking failed.[/yellow]\n"
        f"Keys may be written to swap if memory pressure is high.\n"
        f"Run: [bold]ulimit -l unlimited[/bold] then restart.\n"
        f"Detail: {message}",
        title="[yellow]⚠ Memory Warning[/yellow]",
        border_style="yellow",
    ))


def warn_hibernation_enabled(platform: str) -> None:
    """Display a warning when hibernation is enabled."""
    console.print(Panel(
        f"[yellow]Hibernation is enabled on this system.[/yellow]\n"
        f"If the system hibernates while a vault is open, key material\n"
        f"may be written to disk (hiberfil.sys / sleepimage).\n"
        f"See [bold]docs/SECURITY.md[/bold] for instructions to disable hibernation.",
        title="[yellow]⚠ Hibernation Warning[/yellow]",
        border_style="yellow",
    ))


def warn_swap_active() -> None:
    """Display a warning when swap is active."""
    console.print(
        "[yellow]⚠ Swap is active. "
        "Consider disabling it: sudo swapoff -a[/yellow]",
        file=sys.stderr,
    )


def warn_no_tpm() -> None:
    """Display info when TPM is not available (v2.0 feature)."""
    console.print(
        "[dim]ℹ TPM hardware binding not available on this system. "
        "Running in software-only SECURE mode.[/dim]"
    )


def display_security_mode(mode: str) -> None:
    """Display the current security mode at startup."""
    colours = {
        "KERNEL": "green",
        "SECURE": "cyan",
        "PORTABLE": "yellow",
    }
    colour = colours.get(mode, "white")
    console.print(
        f"[{colour}]Security mode: {mode}[/{colour}]",
        highlight=False,
    )
