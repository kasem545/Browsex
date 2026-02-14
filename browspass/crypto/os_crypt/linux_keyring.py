"""Linux libsecret/secretstorage key extraction for Chromium browsers."""

import logging
from hashlib import pbkdf2_hmac

logger = logging.getLogger(__name__)


def get_linux_key(service_name: str) -> bytes | None:
    """Extract and derive the master encryption key from Linux libsecret.

    Linux stores the encryption password in libsecret (via secretstorage).
    Falls back to default "peanuts" if no password is found.
    Derives the AES-128-CBC key using PBKDF2-HMAC-SHA1.

    Args:
        service_name: Secret service name (e.g., "Chrome Safe Storage")

    Returns:
        16-byte AES-128-CBC key
    """
    password = b"peanuts"

    try:
        import secretstorage  # type: ignore[import-not-found]
    except ImportError:
        logger.debug("secretstorage not available, using default key")
        key = pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)
        return key

    try:
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)

        for item in collection.get_all_items():
            if service_name in item.get_label():
                password = item.get_secret()
                break

        key = pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)
        return key

    except Exception as e:
        logger.debug(f"Failed to extract key from libsecret: {e}")
        key = pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)
        return key
