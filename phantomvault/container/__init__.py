"""
PhantomVault — container package
Handles the vault container file: creation, reading, writing.
All cryptographic operations are delegated to the Rust TCB.
"""

from .portable import PortableContainer

__all__ = ["PortableContainer"]
