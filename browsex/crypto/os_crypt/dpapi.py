"""Windows DPAPI key extraction for Chromium browsers."""

import base64
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def get_windows_key(
    local_state_path: Path, masterkey_hex: str | None = None
) -> bytes | None:
    """Extract and decrypt the master encryption key from Chrome's Local State file.

    Chrome v80+ stores a Base64-encoded, DPAPI-encrypted master key in the Local State JSON file.
    The key has a 5-byte "DPAPI" prefix that must be removed before decryption.

    Supports two modes:
    1. Windows with pywin32: Uses CryptUnprotectData (requires original Windows system)
    2. Cross-platform with masterkey: Uses provided DPAPI masterkey (for exfiltrated profiles)

    Args:
        local_state_path: Path to Chrome's "Local State" file
        masterkey_hex: Optional 64-byte hex DPAPI masterkey for cross-platform decryption

    Returns:
        32-byte AES-256 master key, or None if extraction fails

    Raises:
        ImportError: If pywin32 not installed and no masterkey provided
        FileNotFoundError: If Local State file doesn't exist
        ValueError: If encrypted_key format is invalid
    """
    if masterkey_hex:
        try:
            from dpapick3 import blob as dpapi_blob  # type: ignore[import-untyped]
        except ImportError as e:
            raise ImportError(
                "dpapick3 required for cross-platform DPAPI decryption. "
                "Install with: pip install dpapick3"
            ) from e
    else:
        try:
            import win32crypt  # type: ignore[import-untyped]
        except ImportError as e:
            raise ImportError(
                "pywin32 required for Windows Chrome decryption, "
                "OR provide --masterkey for cross-platform decryption. "
                "Install pywin32: pip install pywin32"
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

    if masterkey_hex:
        try:
            masterkey_bytes = bytes.fromhex(masterkey_hex)
            if len(masterkey_bytes) != 64:
                raise ValueError(
                    f"Masterkey must be 64 bytes (128 hex chars), got {len(masterkey_bytes)} bytes"
                )

            blob = dpapi_blob.DPAPIBlob(encrypted_key)
            if blob.decrypt(masterkey_bytes):
                cleartext = bytes(blob.cleartext)
                logger.info(
                    f"Decrypted {len(cleartext)}-byte key using provided masterkey"
                )
                return cleartext
            else:
                logger.error(
                    f"DPAPI decryption failed. Required masterkey GUID: {blob.mkguid}"
                )
                return None

        except ValueError as e:
            logger.error(f"Invalid masterkey format: {e}")
            return None
        except Exception as e:
            logger.error(f"DPAPI decryption with masterkey failed: {e}")
            return None
    else:
        try:
            result = bytes(
                win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            )

            if len(result) != 32:
                logger.warning(
                    f"Unexpected key length: {len(result)} bytes (expected 32)"
                )

            return result

        except Exception as e:
            logger.error(f"DPAPI decryption failed: {e}")
            return None
