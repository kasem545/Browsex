"""Brave browser password extraction and decryption."""

from browspass.browsers.chromium import ChromiumDecryptor


class Brave(ChromiumDecryptor):
    """Brave browser password decryptor."""

    @property
    def keychain_service_name(self) -> str:
        return "Brave Safe Storage"
