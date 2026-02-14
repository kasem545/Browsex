"""Firefox password extraction and decryption."""

import logging
import sqlite3
from base64 import b64decode
from pathlib import Path

import orjson

from browspass.crypto.nss_crypto import decrypt_login_field, decrypt_pbe
from browspass.models import LoginEntry

logger = logging.getLogger(__name__)

CKA_ID = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
PASSWORD_CHECK_VALUE = b"password-check\x02\x02"


class FirefoxDecryptor:
    def __init__(self, profile_path: Path, master_password: str = "") -> None:
        self.profile_path = profile_path
        self.master_password = master_password.encode("utf-8")
        self._master_key: bytes | None = None

    @property
    def key_db_path(self) -> Path:
        return self.profile_path / "key4.db"

    @property
    def logins_path(self) -> Path:
        return self.profile_path / "logins.json"

    def _extract_master_key(self) -> bytes:
        if not self.key_db_path.exists():
            raise FileNotFoundError(
                f"key4.db not found at {self.key_db_path}. "
                "This tool requires Firefox 58+ (key4.db format)."
            )

        with sqlite3.connect(self.key_db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT item1, item2 FROM metadata WHERE id = 'password';")
            row = cursor.fetchone()
            if not row:
                raise ValueError("Password metadata not found in key4.db")

            global_salt, encrypted_check = row

            logger.info("Verifying master password")
            plaintext_check, _ = decrypt_pbe(
                encrypted_check, self.master_password, global_salt
            )

            if plaintext_check != PASSWORD_CHECK_VALUE:
                raise ValueError(
                    "Master password verification failed. "
                    "Provide correct master password via -p/--password."
                )

            logger.info("Master password verified")

            cursor.execute("SELECT a11, a102 FROM nssPrivate;")
            master_key_data = None
            for row in cursor:
                if row[1] == CKA_ID:
                    master_key_data = row[0]
                    break

            if not master_key_data:
                raise ValueError("Master key not found in nssPrivate table")

            final_key, _ = decrypt_pbe(
                master_key_data, self.master_password, global_salt
            )

            logger.info("Master key extracted: %s", final_key.hex()[:32] + "...")
            return final_key

    @property
    def master_key(self) -> bytes:
        if self._master_key is None:
            self._master_key = self._extract_master_key()
        return self._master_key

    def extract_logins(self) -> list[LoginEntry]:
        if not self.logins_path.exists():
            raise FileNotFoundError(f"logins.json not found at {self.logins_path}")

        data = orjson.loads(self.logins_path.read_bytes())
        logins = data.get("logins", [])

        if not logins:
            logger.warning("No login entries found in logins.json")
            return []

        results: list[LoginEntry] = []
        for entry in logins:
            try:
                username_encrypted = b64decode(entry["encryptedUsername"])
                password_encrypted = b64decode(entry["encryptedPassword"])

                username = decrypt_login_field(username_encrypted, self.master_key)
                password = decrypt_login_field(password_encrypted, self.master_key)

                results.append(
                    LoginEntry(
                        origin_url=entry["hostname"],
                        username=username,
                        password=password,
                    )
                )
            except Exception as e:
                logger.error("Failed to decrypt %s: %s", entry.get("hostname"), e)

        logger.info("Successfully decrypted %d/%d logins", len(results), len(logins))
        return results
