"""Opera browser password extraction and decryption."""

from browspass.browsers.chromium import ChromiumDecryptor


class Opera(ChromiumDecryptor):
    """Opera browser password decryptor."""

    @property
    def keychain_service_name(self) -> str:
        return "Opera Safe Storage"
