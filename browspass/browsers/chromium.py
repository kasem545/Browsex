"""Base class for Chromium-based browser password extraction."""

import json
import logging
import platform
import shutil
import sqlite3
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from browspass.crypto.os_crypt import (
    get_linux_key,
    get_macos_key,
    get_windows_key,
)
from browspass.models import BookmarkEntry, HistoryEntry, LoginEntry
from browspass.utils import find_chrome_local_state, find_file

logger = logging.getLogger(__name__)


class ChromiumDecryptor(ABC):
    """Base class for Chromium-based browser password extraction.

    Handles encryption version detection (v10, v11, v20, DPAPI) and decryption
    for Chrome, Brave, Edge, and Opera browsers.
    """

    def __init__(self, profile_path: Path) -> None:
        self.profile_path = profile_path
        self._decryption_key: bytes | None = None
        self._login_data_path: Path | None = None
        self._local_state_path: Path | None = None
        self._bookmarks_path: Path | None = None
        self._history_path: Path | None = None
        self._validate_profile()

    @property
    def login_data_path(self) -> Path:
        if self._login_data_path is None:
            found = find_file(self.profile_path, "Login Data", max_depth=3)
            if found:
                self._login_data_path = found
            else:
                self._login_data_path = self.profile_path / "Login Data"
        return self._login_data_path

    @property
    def local_state_path(self) -> Path:
        if self._local_state_path is None:
            found = find_chrome_local_state(self.profile_path)
            if found:
                self._local_state_path = found
            else:
                self._local_state_path = self.profile_path.parent / "Local State"
        return self._local_state_path

    @property
    def bookmarks_path(self) -> Path:
        if self._bookmarks_path is None:
            found = find_file(self.profile_path, "Bookmarks", max_depth=3)
            if found:
                self._bookmarks_path = found
            else:
                self._bookmarks_path = self.profile_path / "Bookmarks"
        return self._bookmarks_path

    @property
    def history_path(self) -> Path:
        if self._history_path is None:
            found = find_file(self.profile_path, "History", max_depth=3)
            if found:
                self._history_path = found
            else:
                self._history_path = self.profile_path / "History"
        return self._history_path

    @property
    @abstractmethod
    def keychain_service_name(self) -> str:
        """Return the macOS Keychain service name for this browser."""

    def _validate_profile(self) -> None:
        if not self.profile_path.exists():
            logger.warning("Profile directory not found: %s", self.profile_path)
            return

        if not self.profile_path.is_dir():
            logger.warning("Profile path is not a directory: %s", self.profile_path)
            return

        if not self.login_data_path.exists():
            logger.debug(
                "Login Data not found at %s (will fail during extraction if needed)",
                self.login_data_path,
            )

        if not self.local_state_path.exists():
            logger.debug(
                "Local State not found at %s (may affect decryption on v80+)",
                self.local_state_path,
            )

    def _get_decryption_key(self) -> bytes:
        system = platform.system()
        if system == "Windows":
            key = get_windows_key(self.local_state_path)
            if not key:
                raise ValueError(
                    "Failed to extract Windows DPAPI key. "
                    "Ensure you have access to the user's DPAPI master key."
                )
            return key
        elif system == "Darwin":
            key = get_macos_key(self.keychain_service_name)
            if not key:
                raise ValueError(
                    "Failed to extract macOS Keychain key. "
                    "Install keyring: pip install keyring"
                )
            return key
        elif system == "Linux":
            key = get_linux_key(self.keychain_service_name, self.local_state_path)
            if not key:
                raise ValueError(
                    "Failed to extract Linux decryption key.\n"
                    "Chrome v80+ requires secretstorage to decrypt passwords.\n"
                    "Install with: pip install secretstorage\n"
                    'Or install all dependencies: pip install -e ".[linux]"'
                )
            return key
        else:
            raise NotImplementedError(f"Unsupported platform: {system}")

    @property
    def decryption_key(self) -> bytes:
        if self._decryption_key is None:
            self._decryption_key = self._get_decryption_key()
            logger.info("Decryption key obtained for %s", platform.system())
        return self._decryption_key

    def _decrypt_password(self, encrypted_password: bytes) -> str:
        if encrypted_password[:3] == b"v10" or encrypted_password[:3] == b"v11":
            nonce = encrypted_password[3:15]
            ciphertext = encrypted_password[15:-16]
            tag = encrypted_password[-16:]

            cipher = AES.new(self.decryption_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8", errors="replace")

        if encrypted_password[:3] == b"v20":
            nonce = encrypted_password[3:15]
            ciphertext = encrypted_password[15:-16]
            tag = encrypted_password[-16:]

            cipher = AES.new(self.decryption_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8", errors="replace")

        if platform.system() == "Linux":
            iv = b" " * 16
            cipher_cbc = AES.new(self.decryption_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher_cbc.decrypt(encrypted_password), AES.block_size)
            return plaintext.decode("utf-8", errors="replace")

        raise ValueError("Unsupported password encryption format")

    def extract_logins(self) -> list[LoginEntry]:
        if not self.login_data_path.exists():
            raise FileNotFoundError(
                f"Login Data not found at {self.login_data_path}\n"
                f"Cannot extract passwords without Login Data file."
            )

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_db_path = temp_file.name

        try:
            shutil.copy2(self.login_data_path, temp_db_path)

            with sqlite3.connect(temp_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT origin_url, username_value, password_value, "
                    "date_created, times_used FROM logins"
                )

                results: list[LoginEntry] = []
                for row in cursor:
                    (
                        origin_url,
                        username,
                        encrypted_password,
                        date_created,
                        times_used,
                    ) = row

                    if not encrypted_password:
                        continue

                    try:
                        password = self._decrypt_password(encrypted_password)
                        results.append(
                            LoginEntry(
                                origin_url=origin_url,
                                username=username,
                                password=password,
                                date_created=date_created,
                                times_used=times_used,
                            )
                        )
                    except Exception as e:
                        logger.error(
                            "Failed to decrypt password for %s: %s", origin_url, e
                        )

                logger.info("Successfully decrypted %d logins", len(results))
                return results

        finally:
            Path(temp_db_path).unlink(missing_ok=True)

    def extract_bookmarks(self) -> list[BookmarkEntry]:
        if not self.bookmarks_path.exists():
            logger.warning("Bookmarks file not found at %s", self.bookmarks_path)
            return []

        try:
            data: dict[str, object] = json.loads(
                self.bookmarks_path.read_text(encoding="utf-8")
            )
            results: list[BookmarkEntry] = []

            def parse_bookmarks(node: dict[str, object], folder: str = "") -> None:
                if "children" in node:
                    children = node["children"]
                    if isinstance(children, list):
                        for child in children:
                            if isinstance(child, dict):
                                name = node.get("name")
                                folder_name = name if isinstance(name, str) else folder
                                parse_bookmarks(child, folder_name)
                elif node.get("type") == "url":
                    url = node.get("url")
                    title = node.get("name")
                    date_added = node.get("date_added")
                    results.append(
                        BookmarkEntry(
                            url=url if isinstance(url, str) else "",
                            title=title if isinstance(title, str) else "",
                            date_added=date_added
                            if isinstance(date_added, int)
                            else None,
                            folder=folder,
                        )
                    )

            if "roots" in data:
                roots = data["roots"]
                if isinstance(roots, dict):
                    for root_key, root_node in roots.items():
                        if isinstance(root_node, dict):
                            parse_bookmarks(root_node, root_key)

            logger.info("Successfully extracted %d bookmarks", len(results))
            return results

        except Exception as e:
            logger.error("Failed to extract bookmarks: %s", e)
            return []

    def extract_history(self) -> list[HistoryEntry]:
        if not self.history_path.exists():
            logger.warning("History file not found at %s", self.history_path)
            return []

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_db_path = temp_file.name

        try:
            shutil.copy2(self.history_path, temp_db_path)

            with sqlite3.connect(temp_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT url, title, visit_count, last_visit_time FROM urls"
                )

                results: list[HistoryEntry] = []
                for row in cursor:
                    url, title, visit_count, last_visit_time = row
                    results.append(
                        HistoryEntry(
                            url=url,
                            title=title,
                            visit_count=visit_count,
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
