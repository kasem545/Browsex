"""macOS Keychain key extraction for Chromium browsers."""

import logging
from hashlib import pbkdf2_hmac

logger = logging.getLogger(__name__)


def get_macos_key(service_name: str) -> bytes | None:
    """Extract and derive the master encryption key from macOS Keychain.

    macOS stores the encryption password in Keychain. This function retrieves it
    and derives the AES-128-CBC key using PBKDF2-HMAC-SHA1.

    Args:
        service_name: Keychain service name (e.g., "Chrome Safe Storage")

    Returns:
        16-byte AES-128-CBC key, or None if extraction fails

    Raises:
        ImportError: If keyring is not installed
    """
    try:
        import keyring  # type: ignore[import-not-found]
    except ImportError as e:
        raise ImportError(
            "keyring required for macOS Chrome decryption. "
            "Install with: pip install keyring"
        ) from e

    try:
        password = keyring.get_password(service_name, service_name.split()[-2])
        if not password:
            logger.warning(f"No password found in Keychain for {service_name}")
            return None

        key = pbkdf2_hmac("sha1", password.encode("utf-8"), b"saltysalt", 1003, 16)
        return key

    except Exception as e:
        logger.error(f"Failed to extract key from Keychain: {e}")
        return None
