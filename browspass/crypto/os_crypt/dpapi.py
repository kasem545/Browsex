"""Windows DPAPI key extraction for Chromium browsers."""

import base64
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def get_windows_key(local_state_path: Path) -> bytes | None:
    """Extract and decrypt the master encryption key from Chrome's Local State file on Windows.

    Chrome v80+ stores a Base64-encoded, DPAPI-encrypted master key in the Local State JSON file.
    The key has a 5-byte "DPAPI" prefix that must be removed before decryption.

    Args:
        local_state_path: Path to Chrome's "Local State" file

    Returns:
        32-byte AES-256 master key, or None if extraction fails

    Raises:
        ImportError: If pywin32 is not installed
        FileNotFoundError: If Local State file doesn't exist
        ValueError: If encrypted_key format is invalid
    """
    try:
        import win32crypt  # type: ignore[import-untyped]
    except ImportError as e:
        raise ImportError(
            "pywin32 required for Windows Chrome decryption. "
            "Install with: pip install pywin32"
        ) from e

    if not local_state_path.exists():
        raise FileNotFoundError(f"Local State not found: {local_state_path}")

    local_state = json.loads(local_state_path.read_bytes())
    encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")

    if not encrypted_key_b64:
        logger.warning("No encrypted_key found in Local State")
        return None

    encrypted_key = base64.b64decode(encrypted_key_b64)

    if not encrypted_key.startswith(b"DPAPI"):
        raise ValueError(
            f"Invalid encrypted_key format: expected 'DPAPI' prefix, "
            f"got {encrypted_key[:5]!r}"
        )

    encrypted_key = encrypted_key[5:]

    try:
        decrypted_key: bytes = win32crypt.CryptUnprotectData(
            encrypted_key, None, None, None, 0
        )[1]

        if len(decrypted_key) != 32:
            logger.warning(
                f"Unexpected key length: {len(decrypted_key)} bytes (expected 32)"
            )

        return decrypted_key

    except Exception as e:
        logger.error(f"DPAPI decryption failed: {e}")
        return None
