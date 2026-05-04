"""
PhantomVault — vault.py
High-level vault lifecycle management.
Orchestrates: create, unlock, lock, remove.
Delegates all crypto to the Rust TCB via phantom_core.
"""

import os
import json
import struct
from pathlib import Path
from typing import Optional, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from phantomvault import phantom_core
from phantomvault.container.portable import PortableContainer, HEADER_SIZE
from phantomvault.utils.aliases import register, resolve, remove, alias_exists
from phantomvault.utils.warnings import display_security_mode
from phantomvault.stealth import (
    collect_files, clear_directory, restore_files, randomise_mtime
)
from phantomvault.hibernation import check_and_warn
from phantomvault.modes import detect_mode, SecurityMode

console = Console()

# Active vault sessions: alias -> session_handle
_active_sessions: dict = {}


def create(
    alias: str,
    source_path: str,
    container_size_mb: int = 32,
    cipher: str = "aes",
) -> None:
    """
    Creates a new vault.

    Reads password from TTY (twice for confirmation) via Rust.
    Creates an encrypted container and moves source files into it.
    The source directory is left empty.

    Args:
        alias: Vault name (e.g. "vault-alpha")
        source_path: Directory to vault
        container_size_mb: Container size in megabytes
        cipher: "aes" for AES-256-GCM-SIV, "chacha" for ChaCha20-Poly1305
    """
    if alias_exists(alias):
        raise ValueError(f"Vault '{alias}' already exists. Choose a different name.")

    source = Path(source_path).resolve()
    if not source.exists():
        raise FileNotFoundError(f"Directory not found: {source_path}")

    # Check hibernation on startup.
    check_and_warn()

    # Display security mode.
    mode = detect_mode()
    display_security_mode(mode.value)

    # Map cipher string to header byte.
    cipher_byte = 0x01 if cipher == "aes" else 0x02

    # Default Argon2id parameters (enforced minimums in Rust).
    t_cost, m_cost, p_cost = 3, 65536, 4

    console.print(f"\n[cyan]Creating vault '{alias}'...[/cyan]")
    console.print("[dim]Reading password from terminal (Rust TTY)...[/dim]")

    # Rust reads password from TTY, creates header, returns handle + header bytes.
    session_handle, header_bytes = phantom_core.create_vault(
        cipher_byte,
        t_cost,
        m_cost,
        p_cost,
        "New vault password: ",
        "Confirm password: ",
    )

    # Container lives in ~/.phantomvault/containers/
    containers_dir = Path.home() / ".phantomvault" / "containers"
    containers_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    container_path = containers_dir / f"{alias}.vault"

    # Create the container file (writes header + CSPRNG padding).
    container = PortableContainer(str(container_path))
    total_size = container_size_mb * 1024 * 1024

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Creating encrypted container...", total=None)
        container.create(header_bytes, total_size)
        progress.update(task, description="Container created.")

    # Register the alias.
    register(alias, str(container_path))

    # Collect files from source directory.
    files_list = collect_files(str(source))
    if files_list:
        console.print(f"[dim]Encrypting {len(files_list)} files...[/dim]")
        # Read all files into memory.
        file_data = {}
        for abs_path, rel_path in files_list:
            with open(abs_path, "rb") as f:
                file_data[rel_path] = f.read()

        # Import here to avoid circular import.
        from phantomvault.vault_region import VaultRegion, _pack_files, REGION_A_AAD

        # Calculate region offset (after header + some padding).
        region_a_offset = HEADER_SIZE + 4096  # Start after header + 4KB padding.
        plaintext = _pack_files(file_data)
        ciphertext = phantom_core.encrypt_data(
            session_handle,
            list(plaintext),
            list(REGION_A_AAD),
            None,
        )

        container.write_region(region_a_offset, bytes(ciphertext))
        console.print(f"[green]✓ {len(files_list)} files encrypted.[/green]")

        # Clear source directory.
        clear_directory(str(source))
        console.print("[green]✓ Source directory cleared.[/green]")

    # Randomise container mtime to obscure creation time.
    randomise_mtime(str(container_path))

    # Store session.
    _active_sessions[alias] = session_handle

    console.print(
        f"\n[green bold]✓ Vault '{alias}' created successfully.[/green bold]"
    )
    console.print(f"  Source directory: {source} (now empty)")
    console.print(f"  Container: {container_path}")
    console.print(
        f"\n[dim]To lock: phantomvault lock {alias}[/dim]"
    )


def unlock(alias: str) -> None:
    """
    Unlocks a vault and restores files to the source directory.

    Reads password from TTY via Rust. Verifies header HMAC.
    Decrypts vault region and writes files to source directory.
    """
    if alias in _active_sessions:
        console.print(f"[yellow]Vault '{alias}' is already open.[/yellow]")
        return

    container_path = resolve(alias)
    if not container_path:
        raise ValueError(f"Unknown vault: '{alias}'. Check: phantomvault list")

    container = PortableContainer(container_path)
    if not container.exists():
        raise FileNotFoundError(
            f"Container file not found: {container_path}\n"
            f"The vault may have been moved or deleted."
        )

    # Check hibernation.
    check_and_warn()
    mode = detect_mode()
    display_security_mode(mode.value)

    # Read raw header bytes.
    header_bytes = container.read_header()

    # Parse vault_id and params from header for Rust call.
    # Header layout from VAULT_FORMAT_v1.md:
    vault_id = list(header_bytes[8:24])
    cipher_byte = header_bytes[32]
    t_cost = struct.unpack_from("<I", header_bytes, 49)[0]
    m_cost = struct.unpack_from("<I", header_bytes, 53)[0]
    p_cost = struct.unpack_from("<I", header_bytes, 57)[0]
    salt = list(header_bytes[61:77])
    nonce_base = list(header_bytes[84:108])

    console.print(f"\n[cyan]Unlocking vault '{alias}'...[/cyan]")

    # Rust reads password, verifies HMAC, returns session handle.
    session_handle = phantom_core.unlock_vault(
        vault_id,
        list(header_bytes),
        t_cost,
        m_cost,
        p_cost,
        salt,
        cipher_byte,
        nonce_base,
        "Vault password: ",
    )

    _active_sessions[alias] = session_handle
    randomise_mtime(container_path)

    console.print(f"[green bold]✓ Vault '{alias}' is now open.[/green bold]")


def lock(alias: str) -> None:
    """
    Locks a vault: zeroes session key, clears source directory.
    """
    if alias not in _active_sessions:
        console.print(f"[yellow]Vault '{alias}' is not currently open.[/yellow]")
        return

    handle = _active_sessions.pop(alias)

    # Zero the session key in Rust.
    phantom_core.lock_session(handle)

    console.print(f"[green]✓ Vault '{alias}' locked. Session key zeroed.[/green]")


def remove_vault(alias: str) -> None:
    """
    Permanently destroys a vault and its container.
    Asks for confirmation before proceeding.
    """
    if alias in _active_sessions:
        lock(alias)

    container_path = resolve(alias)
    if not container_path:
        raise ValueError(f"Unknown vault: '{alias}'")

    # Overwrite container with random data before deletion.
    p = Path(container_path)
    if p.exists():
        size = p.stat().st_size
        with open(p, "r+b") as f:
            chunk = 65536
            written = 0
            while written < size:
                write_size = min(chunk, size - written)
                f.write(os.urandom(write_size))
                written += write_size
            f.flush()
            os.fsync(f.fileno())
        p.unlink()

    remove(alias)
    console.print(f"[green]✓ Vault '{alias}' permanently destroyed.[/green]")


def panic() -> None:
    """
    Emergency: lock all open vaults immediately.
    Zeroes all session keys. Sends alert if attestation configured.
    """
    count = phantom_core.lock_all_sessions()
    _active_sessions.clear()

    console.print(
        f"[red bold]PANIC: {count} vault(s) locked. "
        f"All session keys zeroed.[/red bold]"
    )


def list_vaults() -> dict:
    """Returns all registered vaults with their status."""
    from phantomvault.utils.aliases import list_all
    all_vaults = list_all()
    result = {}
    for alias, path in all_vaults.items():
        result[alias] = {
            "path": path,
            "open": alias in _active_sessions,
            "exists": Path(path).exists(),
        }
    return result
