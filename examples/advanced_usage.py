#!/usr/bin/env python3
"""Advanced examples: Output formats, multiple browsers, cross-platform."""

import json
from pathlib import Path

from browsex.browsers import Brave, Chrome, Edge, FirefoxDecryptor, Opera


def extract_with_output_formats():
    """Example: Extract data in different formats."""
    profile = Path.home() / ".config/google-chrome/Default"

    if not profile.exists():
        print("Chrome profile not found")
        return

    chrome = Chrome(profile)

    logins = chrome.extract_logins()
    bookmarks = chrome.extract_bookmarks()

    print("=== JSON Format ===")
    data = {
        "logins": [login.to_dict() for login in logins[:2]],
        "bookmarks": [bm.to_dict() for bm in bookmarks[:2]],
    }
    print(json.dumps(data, indent=2))

    print("\n=== CSV-like Format ===")
    print("URL,Username,Password")
    for login in logins[:3]:
        print(f"{login.origin_url},{login.username},{login.password}")


def extract_all_browsers():
    """Example: Extract from all installed browsers."""
    browsers = {
        "Chrome": (Chrome, Path.home() / ".config/google-chrome/Default"),
        "Brave": (
            Brave,
            Path.home() / ".config/BraveSoftware/Brave-Browser/Default",
        ),
        "Edge": (Edge, Path.home() / ".config/microsoft-edge/Default"),
        "Opera": (Opera, Path.home() / ".config/opera"),
        "Firefox": (
            FirefoxDecryptor,
            Path.home() / ".mozilla/firefox/xxxxxxxx.default-release",
        ),
    }

    for name, (browser_class, profile_path) in browsers.items():
        if not profile_path.exists():
            continue

        try:
            if name == "Firefox":
                browser = browser_class(profile_path, "")
            else:
                browser = browser_class(profile_path)

            logins = browser.extract_logins()
            print(f"{name}: {len(logins)} passwords")
        except Exception as e:
            print(f"{name}: Error - {e}")


def cross_platform_windows_profile():
    """Example: Decrypt Windows Chrome profile on Linux with masterkey."""
    windows_profile = Path("./exfiltrated/Chrome/Default")
    masterkey = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d"

    if not windows_profile.exists():
        print("Windows profile not found")
        print("Expected: ./exfiltrated/Chrome/Default/")
        return

    chrome = Chrome(windows_profile, masterkey_hex=masterkey)

    try:
        logins = chrome.extract_logins()
        print(f"Decrypted {len(logins)} passwords using DPAPI masterkey")

        for login in logins[:5]:
            print(f"  {login.origin_url}: {login.username}")
    except Exception as e:
        print(f"Decryption failed: {e}")
        print("Ensure you provided correct DPAPI masterkey")


def save_to_files():
    """Example: Save extracted data to files."""
    profile = Path.home() / ".config/google-chrome/Default"

    if not profile.exists():
        print("Chrome profile not found")
        return

    chrome = Chrome(profile)

    logins = chrome.extract_logins()
    bookmarks = chrome.extract_bookmarks()
    history = chrome.extract_history()

    output_dir = Path("./browser_data")
    output_dir.mkdir(exist_ok=True)

    (output_dir / "passwords.json").write_text(
        json.dumps([login.to_dict() for login in logins], indent=2)
    )

    (output_dir / "bookmarks.json").write_text(
        json.dumps([bm.to_dict() for bm in bookmarks], indent=2)
    )

    (output_dir / "history.json").write_text(
        json.dumps([entry.to_dict() for entry in history], indent=2)
    )

    print(f"Data saved to {output_dir}/")
    print(f"  - passwords.json ({len(logins)} entries)")
    print(f"  - bookmarks.json ({len(bookmarks)} entries)")
    print(f"  - history.json ({len(history)} entries)")


if __name__ == "__main__":
    print("=== Example 1: Output Formats ===")
    extract_with_output_formats()

    print("\n=== Example 2: All Browsers ===")
    extract_all_browsers()

    print("\n=== Example 3: Save to Files ===")
    save_to_files()

    print("\n=== Example 4: Cross-Platform (commented) ===")
    print("# Uncomment cross_platform_windows_profile() to test")
    print("# Requires Windows Chrome profile + DPAPI masterkey")
