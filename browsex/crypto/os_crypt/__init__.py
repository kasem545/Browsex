"""OS-specific encryption key extraction for Chromium browsers."""

from browsex.crypto.os_crypt.dpapi import get_windows_key
from browsex.crypto.os_crypt.keychain import get_macos_key
from browsex.crypto.os_crypt.linux_keyring import get_linux_key

__all__ = ["get_windows_key", "get_macos_key", "get_linux_key"]
