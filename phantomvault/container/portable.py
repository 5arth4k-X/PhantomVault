"""
PhantomVault — container/portable.py
Portable vault container backend.
Works on Linux, macOS, and Windows without root access.
Uses Rust AES-256-GCM-SIV via phantom_core for all encryption.

Container file layout:
  [0   - 255 ]  256-byte authenticated header
  [256 - EOF ]  CSPRNG padding + encrypted vault regions
"""

import os
import struct
from pathlib import Path
from typing import Optional

from phantomvault import phantom_core

# Header size as defined in VAULT_FORMAT_v1.md
HEADER_SIZE = 256

# Minimum useful container size: header + two small regions + padding
MIN_CONTAINER_SIZE = HEADER_SIZE + (64 * 1024)  # 256 bytes + 64 KB


class PortableContainer:
    """
    Manages the vault container file.
    Reads and writes header and encrypted regions.
    Never holds decrypted data — passes bytes to/from Rust.
    """

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        """Returns True if the container file exists."""
        return self.path.exists()

    def create(
        self,
        header_bytes: bytes,
        total_size: int = 32 * 1024 * 1024,  # 32 MB default
    ) -> None:
        """
        Creates a new container file.

        Writes the header then fills the remaining space with
        CSPRNG random bytes. Both vault regions appear as
        high-entropy data indistinguishable from the padding.

        Args:
            header_bytes: 256-byte authenticated header from Rust.
            total_size: Total container size in bytes (default 32 MB).
        """
        if len(header_bytes) != HEADER_SIZE:
            raise ValueError(
                f"Header must be {HEADER_SIZE} bytes, got {len(header_bytes)}"
            )
        if total_size < MIN_CONTAINER_SIZE:
            raise ValueError(
                f"Container must be at least {MIN_CONTAINER_SIZE} bytes"
            )

        # Create parent directories if needed.
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.path, "wb") as f:
            # Write the authenticated header.
            f.write(bytes(header_bytes))

            # Fill remainder with CSPRNG random bytes.
            # Written in chunks to avoid large memory allocation.
            remaining = total_size - HEADER_SIZE
            chunk_size = 64 * 1024  # 64 KB chunks
            while remaining > 0:
                write_size = min(chunk_size, remaining)
                f.write(bytes(phantom_core.random_bytes(write_size)))
                remaining -= write_size

        # Set restrictive permissions: owner read/write only.
        os.chmod(self.path, 0o600)

    def read_header(self) -> bytes:
        """
        Reads the 256-byte header from the container file.
        Returns raw bytes — Rust will parse and verify.
        """
        if not self.exists():
            raise FileNotFoundError(f"Vault container not found: {self.path}")

        with open(self.path, "rb") as f:
            header = f.read(HEADER_SIZE)

        if len(header) != HEADER_SIZE:
            raise ValueError(
                f"Container file too small: expected at least {HEADER_SIZE} bytes"
            )
        return header

    def write_header(self, header_bytes: bytes) -> None:
        """
        Overwrites the header in the container file.
        Used after incrementing the write counter.
        """
        if len(header_bytes) != HEADER_SIZE:
            raise ValueError(f"Header must be {HEADER_SIZE} bytes")

        with open(self.path, "r+b") as f:
            f.seek(0)
            f.write(header_bytes)
            f.flush()
            os.fsync(f.fileno())

    def read_region(self, offset: int, length: int) -> bytes:
        """
        Reads a vault region (encrypted ciphertext) from the container.

        Args:
            offset: Byte offset from file start.
            length: Number of bytes to read.
        """
        if offset < HEADER_SIZE:
            raise ValueError("Region offset must be after the header")

        with open(self.path, "rb") as f:
            f.seek(offset)
            data = f.read(length)

        if len(data) != length:
            raise ValueError(
                f"Could not read {length} bytes at offset {offset}: "
                f"file may be truncated"
            )
        return data

    def write_region(self, offset: int, data: bytes) -> None:
        """
        Writes encrypted ciphertext to a vault region in the container.

        Args:
            offset: Byte offset from file start.
            data: Encrypted ciphertext bytes to write.
        """
        if offset < HEADER_SIZE:
            raise ValueError("Region offset must be after the header")

        with open(self.path, "r+b") as f:
            f.seek(offset)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    def size(self) -> int:
        """Returns the total size of the container file in bytes."""
        return self.path.stat().st_size

    def delete(self) -> None:
        """Deletes the container file."""
        if self.path.exists():
            self.path.unlink()
