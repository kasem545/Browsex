# Browsex - Multi-Browser Password Extraction Tool

**WARNING: This tool is intended for legitimate password recovery and forensic analysis ONLY. Use responsibly and legally.**

Comprehensive multi-browser password extraction and decryption utility supporting:
- **Chromium-based browsers**: Chrome, Brave, Microsoft Edge, Opera
- **Firefox** (key4.db + logins.json with NSS crypto)

## Features

- **5 Browsers Supported**: Chrome, Brave, Edge, Opera, Firefox
- **3 Data Types**: Passwords, Bookmarks, Browsing History
- **Flexible Extraction**: Extract single or multiple data types with flags
- **Encryption Support**:
  - Chrome v10/v11 (AES-256-GCM with nonce/tag)
  - Chrome DPAPI (pre-v80 legacy support)
  - Chrome v20 (App-Bound Encryption)
  - Firefox v10/v11 (modern binary format)
  - Firefox 3DES-CBC and AES-256-CBC (PBES2)
- **Cross-Platform**: Windows (DPAPI), macOS (Keychain), Linux (libsecret/secretstorage)
- **Auto-Detection**: Automatically detect browser from profile path
- **Clean Architecture**: Modular crypto layer, browser-specific implementations, unified CLI
- **Type-Safe**: 100% mypy strict compliance with full type hints
- **Multiple Output Formats**: text, JSON, CSV

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/Extract-Browsex.git
cd Extract-Browsex

# Create virtual environment
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with platform-specific dependencies
# On Windows:
uv pip install -e ".[windows]"

# On macOS:
uv pip install -e ".[macos]"

# On Linux (REQUIRED for Chrome v80+ password decryption):
uv pip install -e ".[linux]"

# Or install all dependencies:
uv pip install -e ".[windows,macos,linux]"
```

**⚠️ Linux Users**: Chrome v80+ requires `secretstorage` to decrypt passwords. If you see "secretstorage not installed" errors, see [INSTALL_LINUX.md](INSTALL_LINUX.md) for detailed troubleshooting.

## Usage

### Data Type Flags

Extract different types of data from browsers:

- `--passwords` - Extract saved passwords (default if no flags specified)
- `--bookmarks` - Extract bookmarks
- `--history` - Extract browsing history
- `--all` - Extract all data types

**You can combine multiple flags:**

```bash
# Extract passwords and bookmarks
browsex chrome -p /path --passwords --bookmarks

# Extract all data types
browsex chrome -p /path --all

# Extract only history
browsex firefox -p /path --history
```

### Chrome

```bash
# Passwords only (default)
browsex chrome -p ~/.config/google-chrome/Default

# Bookmarks only
browsex chrome -p ~/.config/google-chrome/Default --bookmarks

# Everything as JSON
browsex chrome -p ~/.config/google-chrome/Default --all -f json

# Passwords and history as CSV
browsex chrome -p ~/.config/google-chrome/Default --passwords --history -f csv

# Windows example
browsex chrome -p "%LOCALAPPDATA%\Google\Chrome\User Data\Default" --all

# Cross-platform: Decrypt Windows profile on Linux (requires DPAPI masterkey)
browsex chrome -p "User Data/Default" --passwords -k 1a2b3c4d5e6f...64byte_hex

# Save results to file
browsex chrome -p ~/.config/google-chrome/Default --all -f json -o passwords.json
```

### Brave

```bash
browsex brave -p /path/to/brave/profile --passwords --bookmarks
browsex brave -p /path/to/brave/profile --all -f json -o brave_data.json
```

### Microsoft Edge

```bash
browsex edge -p /path/to/edge/profile --bookmarks
browsex edge -p /path/to/edge/profile --all -f csv
```

### Opera

```bash
browsex opera -p /path/to/opera/profile --history
browsex opera -p /path/to/opera/profile --passwords --bookmarks
```

### Firefox

```bash
# With master password
browsex firefox -p /path/to/firefox/profile -m "master_password" --all

# Without master password (bookmarks/history only)
browsex firefox -p /path/to/firefox/profile --bookmarks --history

# Everything as JSON saved to file
browsex firefox -p /path/to/firefox/profile -m "pass" --all -f json -o firefox_data.json
```

### Auto-Detect Browser

```bash
# Auto-detect and extract passwords
browsex auto -p /path/to/profile

# Auto-detect and extract all data
browsex auto -p /path/to/profile --all

# Auto-detect with custom flags
browsex auto -p /path/to/profile --passwords --bookmarks -f json
```

### General Options

- `-p, --profile-path PATH`: Path to browser profile directory (required)
- `-f, --format {text|json|csv}`: Output format (default: text)
- `-o, --output FILE`: Output file path (default: print to stdout)
- `-m, --master-password PASSWORD`: Firefox master password (if set)
- `-k, --masterkey HEX`: DPAPI masterkey for cross-platform Windows profile decryption
- `--passwords`: Extract passwords (default if no data flags specified)
- `--bookmarks`: Extract bookmarks
- `--history`: Extract browsing history
- `--all`: Extract all data types
- `-v, --verbose`: Enable verbose logging

## Finding Browser Profile Paths

### Chrome
- **Linux**: `~/.config/google-chrome/Default/`
- **macOS**: `~/Library/Application Support/Google/Chrome/Default/`
- **Windows**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`

### Brave
- **Linux**: `~/.config/BraveSoftware/Brave-Browser/Default/`
- **macOS**: `~/Library/Application Support/BraveSoftware/Brave-Browser/Default/`
- **Windows**: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\`

### Microsoft Edge
- **Linux**: `~/.config/microsoft-edge/Default/`
- **macOS**: `~/Library/Application Support/Microsoft Edge/Default/`
- **Windows**: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\`

### Opera
- **Linux**: `~/.config/opera/`
- **macOS**: `~/Library/Application Support/com.operasoftware.Opera/`
- **Windows**: `%APPDATA%\Opera Software\Opera Stable\`

### Firefox
- **Linux**: `~/.mozilla/firefox/xxxxxxxx.default-release/`
- **macOS**: `~/Library/Application Support/Firefox/Profiles/xxxxxxxx.default-release/`
- **Windows**: `%APPDATA%\Mozilla\Firefox\Profiles\xxxxxxxx.default-release\`

## Output Formats

All data types can be exported in multiple formats:

- **text** (default): Human-readable output with section headers
- **json**: Structured JSON with separate arrays for each data type
- **csv**: Spreadsheet-compatible format (one CSV section per data type)

### Example JSON Output

```json
{
  "passwords": [
    {
      "origin_url": "https://example.com",
      "username": "user@example.com",
      "password": "secret123",
      "date_created": 13324567890000000,
      "times_used": 5
    }
  ],
  "bookmarks": [
    {
      "url": "https://github.com",
      "title": "GitHub",
      "date_added": 13324567890000000,
      "folder": "Bookmarks Bar"
    }
  ],
  "history": [
    {
      "url": "https://google.com",
      "title": "Google",
      "visit_count": 42,
      "last_visit_time": 13324567890000000
    }
  ]
}
```

## Security Warnings

1. **Close Browsers First**: All browsers must be closed to avoid database file locks
2. **Master Password**: Firefox with master passwords requires `-m/--master-password`
3. **Plaintext Output**: Decrypted passwords are shown in plaintext - handle output securely
4. **Platform Dependencies**:
   - **Windows**: Requires `pywin32` for DPAPI decryption
   - **macOS**: Requires `keyring` for Keychain access (may prompt for approval)
   - **Linux**: Requires `secretstorage` for libsecret/D-Bus integration
5. **Encryption Support**:
   - Chrome v10/v11/v20: Fully supported
   - Chrome DPAPI (pre-v80): Supported on Windows only
   - App-Bound Encryption (Chrome 127+): Supported with limitations

## Development

```bash
uv pip install -e ".[dev]"
pytest tests/
mypy browsex/
ruff check browsex/
```

## Architecture

```
browsex/
├── models.py                  # Shared LoginEntry dataclass
├── crypto/
│   ├── nss_crypto.py         # Firefox NSS crypto (3DES, AES, PBES2)
│   └── os_crypt/             # Chromium OS-specific crypto
│       ├── dpapi.py          # Windows DPAPI key extraction
│       ├── keychain.py       # macOS Keychain key extraction
│       └── linux_keyring.py  # Linux libsecret key extraction
├── browsers/
│   ├── chromium.py           # Chromium base class (v10/v11/v20/DPAPI)
│   ├── chrome.py             # Google Chrome
│   ├── brave.py              # Brave Browser
│   ├── edge.py               # Microsoft Edge
│   ├── opera.py              # Opera Browser
│   └── firefox.py            # Firefox (NSS-based)
└── cli/
    └── main.py               # Unified CLI interface

tests/
└── unit/
    └── test_nss_crypto.py    # NSS crypto unit tests
```

### Design Principles

- **Modular Crypto Layer**: OS-specific encryption separated from browser logic
- **Inheritance Hierarchy**: Chromium base class → browser-specific implementations
- **Type Safety**: mypy strict mode with 100% type coverage
- **Error Handling**: Graceful fallbacks and informative error messages
- **Cross-Platform**: Automatic platform detection and adaptation

## Legal Notice

This software is provided for **educational and legitimate password recovery purposes only**.

- ✅ Recovering your own passwords from your own devices
- ✅ Forensic analysis with proper authorization
- ❌ Unauthorized access to others' credentials
- ❌ Malicious use

Users are responsible for compliance with applicable laws including CFAA (US), Computer Misuse Act (UK), and local regulations.

## License

MIT License - See LICENSE file for details
