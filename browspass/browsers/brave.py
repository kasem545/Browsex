"""Brave browser password extraction and decryption."""

from pathlib import Path

from browspass.browsers.chromium import ChromiumDecryptor


class Brave(ChromiumDecryptor):
    """Brave browser password decryptor."""

    @property
    def keychain_service_name(self) -> str:
        return "Brave Safe Storage"

    @property
    def login_data_path(self) -> Path:
        return self.profile_path / "Login Data"

    @property
    def local_state_path(self) -> Path:
        return self.profile_path.parent.parent / "Local State"
