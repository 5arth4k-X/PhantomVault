"""
PhantomVault — vault_region.py
Manages the two encrypted vault regions inside a container.

Each region is independently encrypted with a key derived from
a separate password. Accessing one region does not require the
other's password. Each region is described as a "compartment"
for separate categories of files.

All encryption/decryption is delegated to the Rust TCB.
This module never holds decrypted key material.
"""

import json
import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from phantomvault import phantom_core
from phantomvault.container.portable import PortableContainer


# Region identifiers used as AAD in encryption
REGION_A_AAD = b"phantomvault-region-a-v1"
REGION_B_AAD = b"phantomvault-region-b-v1"


class VaultRegion:
    """
    Represents one encrypted compartment within a vault container.
    Handles packing and unpacking file data to/from the container.
    """

    def __init__(
        self,
        container: PortableContainer,
        region_id: str,  # "A" or "B"
        offset: int,
        length: int,
    ) -> None:
        self.container = container
        self.region_id = region_id
        self.offset = offset
        self.length = length
        self.aad = REGION_A_AAD if region_id == "A" else REGION_B_AAD

    def read_encrypted(self) -> bytes:
        """Reads the raw encrypted bytes of this region."""
        return self.container.read_region(self.offset, self.length)

    def write_encrypted(self, ciphertext: bytes) -> None:
        """Writes encrypted bytes to this region in the container."""
        self.container.write_region(self.offset, ciphertext)

    def decrypt_files(
        self,
        session_handle: int,
        write_counter: Optional[int] = None,
    ) -> Dict[str, bytes]:
        """
        Decrypts this region and returns a dict of filename -> bytes.
        Calls Rust for decryption. Never holds decryption key.

        Returns:
            Dict mapping relative file path to file content bytes.
        """
        ciphertext = self.read_encrypted()
        if not ciphertext:
            return {}

        plaintext = phantom_core.decrypt_data(
            session_handle,
            ciphertext,
            self.aad,
            write_counter,
        )

        return _unpack_files(plaintext)

    def encrypt_files(
        self,
        session_handle: int,
        files: Dict[str, bytes],
        write_counter: Optional[int] = None,
    ) -> None:
        """
        Encrypts a dict of filename -> bytes and writes to the container.
        Calls Rust for encryption. Never holds encryption key.

        Args:
            session_handle: Active session handle from Rust.
            files: Dict mapping relative file path to file content bytes.
            write_counter: Current write counter (for ChaCha20 mode).
        """
        plaintext = _pack_files(files)

        ciphertext = phantom_core.encrypt_data(
            session_handle,
            plaintext,
            self.aad,
            write_counter,
        )

        self.write_encrypted(ciphertext)


def _pack_files(files: Dict[str, bytes]) -> bytes:
    """
    Packs multiple files into a single byte stream.
    Format: [count: 4 bytes LE] then for each file:
      [name_len: 4 bytes LE] [name: utf-8] [data_len: 8 bytes LE] [data]
    """
    result = struct.pack("<I", len(files))
    for name, data in files.items():
        name_bytes = name.encode("utf-8")
        result += struct.pack("<I", len(name_bytes))
        result += name_bytes
        result += struct.pack("<Q", len(data))
        result += data
    return result


def _unpack_files(data: bytes) -> Dict[str, bytes]:
    """Unpacks a byte stream back into filename -> bytes dict."""
    if len(data) < 4:
        return {}

    files = {}
    offset = 0

    count = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    for _ in range(count):
        if offset + 4 > len(data):
            break
        name_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        if offset + name_len > len(data):
            break
        name = data[offset: offset + name_len].decode("utf-8")
        offset += name_len

        if offset + 8 > len(data):
            break
        data_len = struct.unpack_from("<Q", data, offset)[0]
        offset += 8

        if offset + data_len > len(data):
            break
        file_data = data[offset: offset + data_len]
        offset += data_len

        files[name] = file_data

    return files
