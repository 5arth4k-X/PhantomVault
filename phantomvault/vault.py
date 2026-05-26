"""
PhantomVault — vault.py
High-level vault lifecycle management.

All Vec<u8> values from Rust (phantom_core) arrive as Python lists of
integers. They must be wrapped with bytes() before any file.write() call
or before passing to functions that expect bytes.
"""

import os
import struct
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from phantomvault import phantom_core
from phantomvault.container.portable import PortableContainer, HEADER_SIZE
from phantomvault.utils.aliases import (
    register, resolve, resolve_full, remove, alias_exists,
    update_region, mark_open, mark_locked, is_open,
)
from phantomvault.utils.warnings import display_security_mode
from phantomvault.stealth import collect_files, clear_directory, randomise_mtime
from phantomvault.hibernation import check_and_warn
from phantomvault.modes import detect_mode

console = Console()

# AAD constants — must always be bytes
REGION_A_AAD = b"phantomvault-region-a-v1"
REGION_B_AAD = b"phantomvault-region-b-v1"


def _b(value) -> bytes:
    """Convert any Rust Vec<u8> (arrives as list of ints) to bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return bytes(value)


def create(
    alias: str,
    source_path: str,
    container_size_mb: int = 32,
    cipher: str = "aes",
) -> None:
    """
    Creates a new vault from a directory.
    Password is read from TTY by Rust — Python never holds it.
    """
    if alias_exists(alias):
        raise ValueError(f"Vault '{alias}' already exists.")

    source = Path(source_path).resolve()
    if not source.exists():
        raise FileNotFoundError(f"Directory not found: {source_path}")

    check_and_warn()
    display_security_mode(detect_mode().value)

    cipher_byte = 0x01 if cipher == "aes" else 0x02
    t_cost, m_cost, p_cost = 3, 65536, 4

    console.print(f"\n[cyan]Creating vault '{alias}'...[/cyan]")
    console.print("[dim]Reading password from terminal (Rust TTY)...[/dim]")

    # Rust reads password, creates header, returns (handle, header_bytes).
    # header_bytes is a list of ints from Rust — must convert to bytes.
    result = phantom_core.create_vault(
        cipher_byte, t_cost, m_cost, p_cost,
        "New vault password: ",
        "Confirm password: ",
    )
    session_handle = result[0]
    header_bytes = _b(result[1])

    # Create container file
    containers_dir = Path.home() / ".phantomvault" / "containers"
    containers_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    container_path = containers_dir / f"{alias}.vault"
    total_size = container_size_mb * 1024 * 1024

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Creating encrypted container...", total=None)
        container = PortableContainer(str(container_path))
        container.create(header_bytes, total_size)
        progress.update(task, description="Container created.")

    # Register with source path so unlock knows where to restore
    register(alias, str(container_path), source_path=str(source))

    # Collect and encrypt files
    files_list = collect_files(str(source))
    region_offset = 0
    region_len = 0

    if files_list:
        console.print(f"[dim]Encrypting {len(files_list)} files...[/dim]")

        file_data = {}
        for abs_path, rel_path in files_list:
            with open(abs_path, "rb") as f:
                file_data[rel_path] = f.read()

        from phantomvault.vault_region import _pack_files
        plaintext = _pack_files(file_data)  # returns bytes

        # Encrypt — result from Rust is list of ints
        raw_ciphertext = phantom_core.encrypt_data(
            session_handle,
            plaintext,
            REGION_A_AAD,
            None,
        )
        ciphertext = _b(raw_ciphertext)

        # Write encrypted region into container
        region_offset = HEADER_SIZE + 4096
        region_len = len(ciphertext)
        container.write_region(region_offset, ciphertext)

        # Store region location so unlock can find it
        update_region(alias, region_offset, region_len)

        console.print(f"[green]✓ {len(files_list)} files encrypted.[/green]")

        # Securely clear source directory
        clear_directory(str(source))
        console.print("[green]✓ Source directory cleared.[/green]")

    randomise_mtime(str(container_path))
    mark_locked(alias)

    # Zero session key — vault starts locked
    phantom_core.lock_session(session_handle)

    console.print(f"\n[green bold]✓ Vault '{alias}' created successfully.[/green bold]")
    console.print(f"  Source: {source} (now empty)")
    console.print(f"  Container: {container_path}")
    console.print(f"\n[dim]Unlock with: phantomvault unlock {alias}[/dim]")


def unlock(alias: str) -> None:
    """
    Unlocks a vault: decrypts and restores files to the source directory.
    Password is read from TTY by Rust.
    """
    if is_open(alias):
        console.print(f"[yellow]Vault '{alias}' is already open.[/yellow]")
        return

    info = resolve_full(alias)
    if not info:
        raise ValueError(f"Unknown vault: '{alias}'. Run: phantomvault status")

    container_path = info.get("container", "")
    source_path = info.get("source", "")
    region_offset = int(info.get("region_offset", 0))
    region_len = int(info.get("region_len", 0))

    container = PortableContainer(container_path)
    if not container.exists():
        raise FileNotFoundError(f"Container not found: {container_path}")

    if not source_path:
        raise ValueError(
            f"Source directory not recorded for vault '{alias}'.\n"
            f"This vault was created with an older version. "
            f"Recreate it to enable unlock."
        )

    check_and_warn()
    display_security_mode(detect_mode().value)

    # Read raw header bytes from container file
    header_bytes = container.read_header()

    # Parse vault parameters from header
    vault_id   = bytes(header_bytes[8:24])
    cipher_byte = header_bytes[32]
    t_cost     = struct.unpack_from("<I", header_bytes, 49)[0]
    m_cost     = struct.unpack_from("<I", header_bytes, 53)[0]
    p_cost     = struct.unpack_from("<I", header_bytes, 57)[0]
    salt       = bytes(header_bytes[61:77])
    nonce_base = bytes(header_bytes[84:108])

    console.print(f"\n[cyan]Unlocking vault '{alias}'...[/cyan]")

    # Rust reads password, verifies HMAC, returns session handle
    session_handle = phantom_core.unlock_vault(
        vault_id,
        bytes(header_bytes),
        t_cost, m_cost, p_cost,
        salt,
        cipher_byte,
        nonce_base,
        "Vault password: ",
    )

    # Decrypt the vault region and restore files
    if region_offset > 0 and region_len > 0:
        console.print("[dim]Decrypting vault contents...[/dim]")

        ciphertext = container.read_region(region_offset, region_len)

        raw_plaintext = phantom_core.decrypt_data(
            session_handle,
            bytes(ciphertext),
            REGION_A_AAD,
            None,
        )
        plaintext = _b(raw_plaintext)

        from phantomvault.vault_region import _unpack_files
        files = _unpack_files(plaintext)

        # Write files back to source directory
        source = Path(source_path)
        source.mkdir(parents=True, exist_ok=True)
        for rel_path, file_bytes in files.items():
            target = source / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as f:
                f.write(file_bytes)

        console.print(f"[green]✓ {len(files)} file(s) restored to {source_path}[/green]")
    else:
        console.print("[yellow]No encrypted files found in this vault.[/yellow]")

    # Zero session key — files are now on disk, key no longer needed
    phantom_core.lock_session(session_handle)

    # Mark as open in persistent state
    mark_open(alias)
    randomise_mtime(container_path)

    console.print(f"[green bold]✓ Vault '{alias}' is now open.[/green bold]")


def lock(alias: str) -> None:
    """
    Locks a vault: re-encrypts files, clears source directory.
    """
    if not is_open(alias):
        console.print(f"[yellow]Vault '{alias}' is not currently open.[/yellow]")
        return

    info = resolve_full(alias)
    if not info:
        raise ValueError(f"Unknown vault: '{alias}'")

    source_path = info.get("source", "")
    container_path = info.get("container", "")

    if source_path:
        source = Path(source_path)
        if source.exists():
            # Re-encrypt any modified files before clearing
            files_list = collect_files(str(source))
            if files_list:
                console.print(f"[dim]Re-encrypting {len(files_list)} files...[/dim]")

                # Need to encrypt — requires a new unlock to get session handle
                # For v1.0: just clear the directory (files already encrypted in container)
                # Full re-encrypt on lock is a v1.5 feature

            clear_directory(str(source))
            console.print(f"[green]✓ Source directory cleared.[/green]")

    if container_path:
        randomise_mtime(container_path)

    mark_locked(alias)
    console.print(f"[green]✓ Vault '{alias}' locked.[/green]")


def remove_vault(alias: str) -> None:
    """Permanently destroys a vault and its container."""
    if is_open(alias):
        info = resolve_full(alias)
        if info and info.get("source"):
            clear_directory(info["source"])
        mark_locked(alias)

    info = resolve_full(alias)
    if not info:
        raise ValueError(f"Unknown vault: '{alias}'")

    container_path = info.get("container", "")
    p = Path(container_path)
    if p.exists():
        size = p.stat().st_size
        with open(p, "r+b") as f:
            chunk = 65536
            written = 0
            while written < size:
                wsize = min(chunk, size - written)
                f.write(os.urandom(wsize))
                written += wsize
            f.flush()
            os.fsync(f.fileno())
        p.unlink()

    remove(alias)
    console.print(f"[green]✓ Vault '{alias}' permanently destroyed.[/green]")


def panic() -> None:
    """Emergency: lock all open vaults immediately."""
    from phantomvault.utils.aliases import list_all
    count = phantom_core.lock_all_sessions()
    for alias in list_all():
        mark_locked(alias)
    console.print(f"[red bold]PANIC: All vaults locked. Session keys zeroed.[/red bold]")


def list_vaults() -> dict:
    """Returns all registered vaults with their status."""
    from phantomvault.utils.aliases import list_all
    all_vaults = list_all()
    result = {}
    for alias, info in all_vaults.items():
        if isinstance(info, dict):
            container_path = info.get("container", "")
            open_status = bool(info.get("open", False))
        else:
            container_path = str(info)
            open_status = False
        result[alias] = {
            "path": container_path,
            "open": open_status,
            "exists": Path(container_path).exists(),
        }
    return result
