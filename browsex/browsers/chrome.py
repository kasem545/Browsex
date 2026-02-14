"""Chrome password extraction and decryption."""

from browsex.browsers.chromium import ChromiumDecryptor


class Chrome(ChromiumDecryptor):
    """Chrome browser password decryptor."""

    @property
    def keychain_service_name(self) -> str:
        return "Chrome Safe Storage"
