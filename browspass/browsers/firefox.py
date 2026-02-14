"""Firefox password extraction and decryption."""

import logging
import sqlite3
import tempfile
from base64 import b64decode
from pathlib import Path
from shutil import copy2

import orjson

from browspass.crypto.nss_crypto import decrypt_login_field, decrypt_pbe
from browspass.models import BookmarkEntry, HistoryEntry, LoginEntry

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

    @property
    def places_path(self) -> Path:
        return self.profile_path / "places.sqlite"

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

            master_key_candidates = []
            for row in cursor:
                if row[1] == CKA_ID:
                    master_key_candidates.append(row[0])

            if not master_key_candidates:
                raise ValueError("Master key not found in nssPrivate table")

            logger.debug("Found %d master key candidate(s)", len(master_key_candidates))

            for i, master_key_data in enumerate(master_key_candidates):
                final_key, algo = decrypt_pbe(
                    master_key_data, self.master_password, global_salt
                )
                logger.debug(
                    "Master key candidate %d (algo: %s): %s (length: %d bytes)",
                    i,
                    algo,
                    final_key.hex()[:64] + "...",
                    len(final_key),
                )

            if len(master_key_candidates) > 1:
                final_key_48, _ = decrypt_pbe(
                    master_key_candidates[-1], self.master_password, global_salt
                )
                if len(final_key_48) == 48:
                    logger.info("Using 48-byte master key for AES-256-CBC")
                    return final_key_48

            final_key, _ = decrypt_pbe(
                master_key_candidates[0], self.master_password, global_salt
            )
            logger.info(
                "Master key extracted: %s (length: %d bytes)",
                final_key.hex()[:64] + "...",
                len(final_key),
            )
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
                username = ""
                password = ""

                if "encryptedUsername" in entry and entry["encryptedUsername"]:
                    username_encrypted = b64decode(entry["encryptedUsername"])
                    username = decrypt_login_field(username_encrypted, self.master_key)

                if "encryptedPassword" in entry and entry["encryptedPassword"]:
                    password_encrypted = b64decode(entry["encryptedPassword"])
                    password = decrypt_login_field(password_encrypted, self.master_key)

                results.append(
                    LoginEntry(
                        origin_url=entry.get("hostname", "Unknown"),
                        username=username,
                        password=password,
                    )
                )
            except Exception as e:
                logger.error("Failed to decrypt %s: %s", entry.get("hostname"), e)

        logger.info("Successfully decrypted %d/%d logins", len(results), len(logins))
        return results

    def extract_bookmarks(self) -> list[BookmarkEntry]:
        if not self.places_path.exists():
            logger.warning("places.sqlite not found at %s", self.places_path)
            return []

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_db_path = temp_file.name

        try:
            copy2(self.places_path, temp_db_path)

            with sqlite3.connect(temp_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT p.url, b.title, b.dateAdded, b.parent "
                    "FROM moz_bookmarks b "
                    "JOIN moz_places p ON b.fk = p.id "
                    "WHERE b.type = 1 AND p.url IS NOT NULL"
                )

                results: list[BookmarkEntry] = []
                for row in cursor:
                    url, title, date_added, parent_id = row
                    results.append(
                        BookmarkEntry(
                            url=url,
                            title=title or "",
                            date_added=date_added,
                            folder=str(parent_id) if parent_id else None,
                        )
                    )

                logger.info("Successfully extracted %d bookmarks", len(results))
                return results

        except Exception as e:
            logger.error("Failed to extract bookmarks: %s", e)
            return []

        finally:
            Path(temp_db_path).unlink(missing_ok=True)

    def extract_history(self) -> list[HistoryEntry]:
        if not self.places_path.exists():
            logger.warning("places.sqlite not found at %s", self.places_path)
            return []

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_db_path = temp_file.name

        try:
            copy2(self.places_path, temp_db_path)

            with sqlite3.connect(temp_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT p.url, p.title, COUNT(v.id) as visit_count, "
                    "MAX(v.visit_date) as last_visit_time "
                    "FROM moz_places p "
                    "LEFT JOIN moz_historyvisits v ON p.id = v.place_id "
                    "WHERE p.url IS NOT NULL "
                    "GROUP BY p.id"
                )

                results: list[HistoryEntry] = []
                for row in cursor:
                    url, title, visit_count, last_visit_time = row
                    results.append(
                        HistoryEntry(
                            url=url,
                            title=title,
                            visit_count=visit_count or 0,
                            last_visit_time=last_visit_time,
                        )
                    )

                logger.info("Successfully extracted %d history entries", len(results))
                return results

        except Exception as e:
            logger.error("Failed to extract history: %s", e)
            return []

        finally:
            Path(temp_db_path).unlink(missing_ok=True)
