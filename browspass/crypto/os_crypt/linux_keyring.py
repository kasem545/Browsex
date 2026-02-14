"""Linux libsecret/secretstorage key extraction for Chromium browsers."""

import base64
import json
import logging
from hashlib import pbkdf2_hmac
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

logger = logging.getLogger(__name__)


def get_linux_key(
    service_name: str, local_state_path: Path | None = None
) -> bytes | None:
    """Extract and decrypt the master encryption key for Chromium on Linux.

    Chrome v80+ stores an encrypted_key in Local State (similar to Windows),
    encrypted with a password from libsecret. Older versions use PBKDF2
    derivation directly.

    This function attempts both methods:
    1. Modern (v80+): Read Local State, decrypt encrypted_key with libsecret password
    2. Legacy: Derive key using PBKDF2 from libsecret password

    Args:
        service_name: Secret service name (e.g., "Chrome Safe Storage")
        local_state_path: Path to Local State file (for v80+ Chrome)

    Returns:
        16 or 32-byte AES key for password decryption
    """
    password = b"peanuts"

    try:
        import secretstorage  # type: ignore[import-not-found]
    except ImportError:
        logger.warning(
            "secretstorage not installed - cannot decrypt Chrome v80+ passwords. "
            "Install with: pip install secretstorage"
        )
        if local_state_path and local_state_path.exists():
            try:
                local_state = json.loads(local_state_path.read_bytes())
                if local_state.get("os_crypt", {}).get("encrypted_key"):
                    logger.error(
                        "Local State contains encrypted_key but secretstorage is not available. "
                        "Cannot decrypt passwords without secretstorage on Linux."
                    )
                    return None
            except Exception:
                pass

        key = pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)
        logger.info("Using PBKDF2-derived key with default password (legacy Chrome)")
        return key

    try:
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)

        for item in collection.get_all_items():
            if service_name in item.get_label():
                password = item.get_secret()
                logger.debug(f"Retrieved password from libsecret for {service_name}")
                break

    except Exception as e:
        logger.debug(f"Failed to extract password from libsecret: {e}")

    if local_state_path and local_state_path.exists():
        try:
            local_state = json.loads(local_state_path.read_bytes())
            encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")

            if encrypted_key_b64:
                encrypted_key = base64.b64decode(encrypted_key_b64)

                if encrypted_key[:3] == b"v10" or encrypted_key[:3] == b"v11":
                    derived_key = pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)

                    nonce = encrypted_key[3:15]
                    ciphertext = encrypted_key[15:]

                    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
                    try:
                        decrypted_key = cipher.decrypt_and_verify(
                            ciphertext[:-16], ciphertext[-16:]
                        )
                        logger.info(
                            f"Decrypted {len(decrypted_key)}-byte key from Local State (v10/v11)"
                        )
                        return decrypted_key
                    except ValueError as e:
                        logger.warning(
                            f"Failed to decrypt v10/v11 encrypted_key: {e}, falling back"
                        )

                elif encrypted_key.startswith(b"DPAPI"):
                    logger.warning(
                        "DPAPI prefix found in Local State on Linux - unexpected format"
                    )

                else:
                    iv = b" " * 16
                    derived_key = pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)
                    cipher_cbc = AES.new(derived_key, AES.MODE_CBC, iv)
                    try:
                        decrypted_key = unpad(
                            cipher_cbc.decrypt(encrypted_key), AES.block_size
                        )
                        logger.info(
                            f"Decrypted {len(decrypted_key)}-byte key from Local State (CBC)"
                        )
                        return decrypted_key
                    except ValueError as e:
                        logger.warning(
                            f"Failed to decrypt CBC encrypted_key: {e}, falling back"
                        )

        except Exception as e:
            logger.debug(f"Failed to decrypt encrypted_key from Local State: {e}")

    key = pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)
    logger.info("Using PBKDF2-derived key (legacy method)")
    return key
