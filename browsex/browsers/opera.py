"""Opera browser password extraction and decryption."""

from browsex.browsers.chromium import ChromiumDecryptor


class Opera(ChromiumDecryptor):
    """Opera browser password decryptor."""

    @property
    def keychain_service_name(self) -> str:
        return "Opera Safe Storage"
