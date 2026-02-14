# Browspass - Multi-Browser Password Decryption Tool

**WARNING: This tool is intended for legitimate password recovery and forensic analysis ONLY. Use responsibly and legally.**

Comprehensive multi-browser password extraction and decryption utility supporting:
- **Chromium-based browsers**: Chrome, Brave, Microsoft Edge, Opera
- **Firefox** (key4.db + logins.json with NSS crypto)

## Features

- **5 Browsers Supported**: Chrome, Brave, Edge, Opera, Firefox
- **Encryption Support**:
  - Chrome v10/v11 (AES-256-GCM with nonce/tag)
  - Chrome DPAPI (pre-v80 legacy support)
  - Chrome v20 (App-Bound Encryption)
  - Firefox 3DES-CBC and AES-256-CBC (PBES2)
- **Cross-Platform**: Windows (DPAPI), macOS (Keychain), Linux (libsecret/secretstorage)
- **Clean Architecture**: Modular crypto layer, browser-specific implementations, unified CLI
- **Type-Safe**: 100% mypy strict compliance with full type hints
- **Multiple Output Formats**: text, JSON, CSV

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/Extract-Browspass.git
cd Extract-Browspass

# Create virtual environment
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with platform-specific dependencies
# On Windows:
uv pip install -e ".[windows]"

# On macOS:
uv pip install -e ".[macos]"

# On Linux:
uv pip install -e ".[linux]"

# Or install all dependencies:
uv pip install -e ".[windows,macos,linux]"
```

## Usage

### Chrome

```bash
browspass chrome -p /path/to/chrome/profile
browspass chrome -p /path/to/chrome/profile -f json
```

### Brave

```bash
browspass brave -p /path/to/brave/profile
browspass brave -p /path/to/brave/profile -f csv
```

### Microsoft Edge

```bash
browspass edge -p /path/to/edge/profile
browspass edge -p /path/to/edge/profile -f json
```

### Opera

```bash
browspass opera -p /path/to/opera/profile
browspass opera -p /path/to/opera/profile -f csv
```

### Firefox

```bash
browspass firefox -p /path/to/firefox/profile
browspass firefox -p /path/to/firefox/profile -m "master_password" -f json
```

### General Options

- `-p, --profile-path PATH`: Path to browser profile directory (required)
- `-f, --format {text|json|csv}`: Output format (default: text)
- `-m, --master-password PASSWORD`: Firefox master password (if set)
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

- **text** (default): Human-readable output
- **json**: Structured JSON for programmatic use
- **csv**: Spreadsheet-compatible format

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
mypy browspass/
ruff check browspass/
```

## Architecture

```
browspass/
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
