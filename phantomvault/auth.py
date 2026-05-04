"""
PhantomVault — auth.py
Authentication orchestration.
v1.0: password only (via Rust TTY input).
v1.5: adds TOTP.
v2.0: adds FIDO2/YubiKey.

Python never holds the password — it triggers the Rust TTY read
which returns only a session handle.
"""


class AuthResult:
    """Result of an authentication attempt."""

    def __init__(self, success: bool, message: str = "") -> None:
        self.success = success
        self.message = message


def verify_totp(totp_secret: str, code: str) -> AuthResult:
    """
    Verifies a TOTP code. Used in v1.5+.
    In v1.0 this always returns success (TOTP not yet implemented).
    """
    # v1.0: TOTP not implemented. Always pass.
    # v1.5: implement with pyotp.
    return AuthResult(success=True)


def is_totp_configured(vault_alias: str) -> bool:
    """Returns True if TOTP is configured for this vault."""
    # v1.0: always False.
    return False
