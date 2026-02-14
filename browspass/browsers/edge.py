"""Microsoft Edge browser password extraction and decryption."""

from browspass.browsers.chromium import ChromiumDecryptor


class Edge(ChromiumDecryptor):
    """Microsoft Edge browser password decryptor."""

    @property
    def keychain_service_name(self) -> str:
        return "Microsoft Edge Safe Storage"
