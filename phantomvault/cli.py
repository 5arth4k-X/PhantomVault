"""
PhantomVault — cli.py
Command-line interface using Typer + Rich.
This is the outermost Python shell. It never holds key material.
All security-sensitive operations are delegated to vault.py
which delegates crypto to the Rust TCB.
"""

import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

app = typer.Typer(
    name="phantomvault",
    help="PhantomVault — Encrypted file vault with Rust cryptographic core.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


def _handle_error(e: Exception) -> None:
    """Displays an error message and exits with code 1."""
    err_console.print(f"[red bold]Error:[/red bold] {e}")
    raise typer.Exit(code=1)


# =============================================================================
# VAULT MANAGEMENT COMMANDS
# =============================================================================

@app.command()
def create(
    alias: str = typer.Argument(..., help="Vault name (e.g. vault-alpha)"),
    path: str = typer.Argument(..., help="Directory to encrypt"),
    size: int = typer.Option(32, "--size", "-s", help="Container size in MB"),
    cipher: str = typer.Option(
        "aes",
        "--cipher", "-c",
        help="Cipher: 'aes' (AES-256-GCM-SIV) or 'chacha' (ChaCha20-Poly1305)",
    ),
) -> None:
    """Create a new encrypted vault from a directory."""
    try:
        from phantomvault.vault import create as _create
        _create(alias, path, container_size_mb=size, cipher=cipher)
    except Exception as e:
        _handle_error(e)


@app.command()
def unlock(
    alias: str = typer.Argument(..., help="Vault name to unlock"),
) -> None:
    """Unlock a vault and restore files to the source directory."""
    try:
        from phantomvault.vault import unlock as _unlock
        _unlock(alias)
    except Exception as e:
        _handle_error(e)


@app.command()
def lock(
    alias: str = typer.Argument(..., help="Vault name to lock"),
) -> None:
    """Lock a vault and zero the session key."""
    try:
        from phantomvault.vault import lock as _lock
        _lock(alias)
    except Exception as e:
        _handle_error(e)


@app.command()
def remove(
    alias: str = typer.Argument(..., help="Vault name to destroy"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """Permanently destroy a vault and its container."""
    if not yes:
        confirmed = typer.confirm(
            f"Permanently destroy vault '{alias}'? This cannot be undone.",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit()
    try:
        from phantomvault.vault import remove_vault
        remove_vault(alias)
    except Exception as e:
        _handle_error(e)


@app.command()
def status() -> None:
    """Show all registered vaults and their current status."""
    try:
        from phantomvault.vault import list_vaults
        from phantomvault.modes import detect_mode

        mode = detect_mode()
        console.print(f"\n[cyan]Security mode: {mode.value}[/cyan]")

        vaults = list_vaults()
        if not vaults:
            console.print("\n[dim]No vaults registered.[/dim]")
            console.print("Create one: [bold]phantomvault create <alias> <path>[/bold]")
            return

        table = Table(title="Registered Vaults", show_header=True)
        table.add_column("Alias", style="bold")
        table.add_column("Status")
        table.add_column("Container exists")
        table.add_column("Path", style="dim")

        for alias, info in vaults.items():
            status_str = "[green]OPEN[/green]" if info["open"] else "[dim]locked[/dim]"
            exists_str = "[green]yes[/green]" if info["exists"] else "[red]MISSING[/red]"
            table.add_row(alias, status_str, exists_str, info["path"])

        console.print(table)
    except Exception as e:
        _handle_error(e)


# =============================================================================
# EMERGENCY
# =============================================================================

@app.command()
def panic() -> None:
    """EMERGENCY: Lock all open vaults and zero all session keys immediately."""
    try:
        from phantomvault.vault import panic as _panic
        _panic()
    except Exception as e:
        _handle_error(e)


# =============================================================================
# RECOVERY
# =============================================================================

recovery_app = typer.Typer(help="Shamir secret sharing recovery operations.")
app.add_typer(recovery_app, name="recovery")


@recovery_app.command("export")
def recovery_export(
    alias: str = typer.Argument(..., help="Open vault to export recovery shares for"),
    shares: int = typer.Option(5, "--shares", "-n", help="Total number of shares"),
    threshold: int = typer.Option(3, "--threshold", "-k", help="Shares needed to recover"),
) -> None:
    """Export Shamir recovery shares for an open vault."""
    console.print(
        f"\n[yellow]Recovery share export — coming in v1.5[/yellow]\n"
        f"Shamir {threshold}-of-{shares} split will be available after "
        f"the v1.0 core is released and audited."
    )


# =============================================================================
# AUDIT
# =============================================================================

audit_app = typer.Typer(help="Audit log operations.")
app.add_typer(audit_app, name="audit")


@audit_app.command("show")
def audit_show(
    alias: str = typer.Argument(..., help="Vault alias"),
) -> None:
    """Display the HMAC-verified audit log for a vault."""
    console.print("[yellow]Audit log — coming in v1.5[/yellow]")


@audit_app.command("verify")
def audit_verify(
    alias: str = typer.Argument(..., help="Vault alias"),
) -> None:
    """Verify the HMAC chain integrity of the audit log."""
    console.print("[yellow]Audit verification — coming in v1.5[/yellow]")



@app.command()
def about() -> None:
    """Learn what PhantomVault is and how it works."""
    console.print("""
[bold cyan]PhantomVault v1.0[/bold cyan]
[dim]Encrypted file vault with a Rust cryptographic core.[/dim]

[bold]What it does[/bold]
PhantomVault takes a directory of files and encrypts them into a single
container file using authenticated encryption. The source directory is
left empty. When you unlock the vault, the files are decrypted back to
their original location. When you lock it, they are removed and the
session key is zeroed from memory.

[bold]Security design[/bold]
All cryptographic operations happen inside a Rust module called
phantom_core. Python handles the user interface and file management
but never holds raw key material. Keys live only in Rust memory,
are locked against swapping (mlock), and are zeroed immediately
when the vault is locked.

[bold]Cryptography used[/bold]
  Encryption : AES-256-GCM-SIV (nonce-misuse-resistant)
               or ChaCha20-Poly1305 (software fallback)
  Key derivation : Argon2id (t=3, m=64MB, p=4 minimum)
  Authentication : HMAC-SHA256 over the vault header
  Secret sharing : Shamir (audited sharks crate)

[bold]Two compartments[/bold]
Each vault has two independent encrypted storage areas, each
accessible with a separate password. Useful for organising
different categories of files with different access credentials.

[bold]What it does not do[/bold]
  - It does not protect against a compromised operating system
  - It does not protect against hardware keyloggers
  - It does not help users circumvent any applicable law
  - It does not guarantee protection if hibernation is enabled

[bold]Licence[/bold]  Apache-2.0
[bold]Source[/bold]   https://github.com/your-username/phantomvault
[bold]Docs[/bold]     See docs/ directory for SECURITY.md and THREAT_MODEL.md
""")


@app.command()
def about() -> None:
    """Learn what PhantomVault is and how it works."""
    console.print("""
[bold cyan]PhantomVault v1.0[/bold cyan]
[dim]Encrypted file vault with a Rust cryptographic core.[/dim]

[bold]What it does[/bold]
PhantomVault takes a directory of files and encrypts them into a single
container file using authenticated encryption. The source directory is
left empty. When you unlock the vault, the files are decrypted back to
their original location. When you lock it, they are removed and the
session key is zeroed from memory.

[bold]Security design[/bold]
All cryptographic operations happen inside a Rust module called
phantom_core. Python handles the user interface and file management
but never holds raw key material. Keys live only in Rust memory,
are locked against swapping (mlock), and are zeroed immediately
when the vault is locked.

[bold]Cryptography used[/bold]
  Encryption : AES-256-GCM-SIV (nonce-misuse-resistant)
               or ChaCha20-Poly1305 (software fallback)
  Key derivation : Argon2id (t=3, m=64MB, p=4 minimum)
  Authentication : HMAC-SHA256 over the vault header
  Secret sharing : Shamir (audited sharks crate)

[bold]Two compartments[/bold]
Each vault has two independent encrypted storage areas, each
accessible with a separate password. Useful for organising
different categories of files with different access credentials.

[bold]What it does not do[/bold]
  - It does not protect against a compromised operating system
  - It does not protect against hardware keyloggers
  - It does not help users circumvent any applicable law
  - It does not guarantee protection if hibernation is enabled

[bold]Licence[/bold]  Apache-2.0
[bold]Source[/bold]   https://github.com/5arth4k-X/phantomvault
[bold]Docs[/bold]     See docs/ directory for SECURITY.md and THREAT_MODEL.md
""")

# =============================================================================
# VERSION
# =============================================================================

@app.command()
def version() -> None:
    """Show PhantomVault version."""
    from phantomvault import __version__
    console.print(f"PhantomVault v{__version__}")
    console.print("[dim]Rust TCB: phantom_core[/dim]")
    console.print("[dim]Cipher: AES-256-GCM-SIV (primary), ChaCha20-Poly1305 (alt)[/dim]")
    console.print("[dim]KDF: Argon2id (t=3, m=64MB, p=4)[/dim]")


# =============================================================================
# ENTRY POINT
# =============================================================================

def main() -> None:
    app()


if __name__ == "__main__":
    main()
