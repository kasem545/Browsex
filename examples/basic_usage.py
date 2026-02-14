#!/usr/bin/env python3
"""Example: Programmatic usage of browspass library."""

from pathlib import Path

from browspass.browsers import ChromeDecryptor, FirefoxDecryptor

firefox_profile = Path.home() / ".mozilla/firefox/xxxxxxxx.default-release"

if firefox_profile.exists():
    decryptor = FirefoxDecryptor(firefox_profile, master_password="")
    logins = decryptor.extract_logins()

    print(f"Found {len(logins)} Firefox logins")
    for login in logins[:3]:
        print(f"  {login.hostname}: {login.username}")

chrome_profile = Path.home() / ".config/google-chrome/Default"

if chrome_profile.exists():
    decryptor = ChromeDecryptor(chrome_profile)
    logins = decryptor.extract_logins()

    print(f"\nFound {len(logins)} Chrome logins")
    for login in logins[:3]:
        print(f"  {login.origin_url}: {login.username}")
