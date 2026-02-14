# Linux Installation Guide

## Quick Fix for "secretstorage not installed" Error

If you see this error:

```
[WARNING] secretstorage not installed - cannot decrypt Chrome v80+ passwords
[ERROR] Local State contains encrypted_key but secretstorage is not available
```

### Solution: Install Linux Dependencies

```bash
# Navigate to browsex directory
cd /home/user/Extract-Browsex

# Install with Linux dependencies (recommended)
pip install -e ".[linux]"

# OR install just secretstorage
pip install secretstorage
```

### Verify Installation

```bash
python3 -c "import secretstorage; print('✓ secretstorage installed successfully')"
```

### Test Password Extraction

```bash
browsex chrome -p "User Data" --passwords

# Expected output:
# [INFO] Decryption key obtained for Linux
# [INFO] Successfully decrypted N logins
```

## Why This is Required

**Chrome v80+ (Released Feb 2020) changed password encryption on Linux:**

- **Before v80**: Simple PBKDF2 derivation with hardcoded "peanuts" salt
- **After v80**: Two-stage encryption:
  1. Random 32-byte master key stored in `Local State` file
  2. Master key encrypted with password from GNOME Keyring (libsecret)
  3. Passwords encrypted with the master key

**Without `secretstorage`**:
- Cannot read password from GNOME Keyring
- Cannot decrypt the master key from Local State
- Cannot decrypt any passwords (MAC check fails)

**Bookmarks/History still work** because they're stored as plaintext JSON/SQLite.

## Platform-Specific Dependencies

### Install All Platform Dependencies

```bash
# On Linux (recommended)
pip install -e ".[linux]"

# On Windows
pip install -e ".[windows]"

# On macOS
pip install -e ".[macos]"

# All platforms (if testing cross-platform)
pip install -e ".[windows,macos,linux]"
```

### What Each Platform Needs

| Platform | Dependency | Purpose |
|----------|-----------|---------|
| **Linux** | `secretstorage>=3.3.0` | Access GNOME Keyring for Chrome v80+ |
| **Windows** | `pywin32>=306` | Access Windows DPAPI for Chrome v80+ |
| **macOS** | `keyring>=24.0.0` | Access macOS Keychain for Chrome v80+ |

## Troubleshooting

### Issue: "D-Bus not available"

If you see:
```
SecretServiceNotAvailableException: Secret Service daemon is not available
```

**Solution**: Ensure D-Bus and GNOME Keyring are running

```bash
# Check if keyring is running
ps aux | grep gnome-keyring

# If not running, start it
gnome-keyring-daemon --start
```

### Issue: "Chrome is running"

If you see file lock errors:

```bash
# Close Chrome completely
pkill -9 chrome
pkill -9 chromium

# Then try again
browsex chrome -p "User Data" --passwords
```

### Issue: "Permission denied"

If running as root or different user:

```bash
# Run as the user who owns the Chrome profile
sudo -u original_user browsex chrome -p "User Data" --passwords
```

## Development Setup

For development with all dependencies:

```bash
# Clone repository
git clone <repo-url>
cd Extract-Browsex

# Create virtual environment (using uv)
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with all dependencies
uv pip install -e ".[windows,macos,linux,dev]"

# Run tests
pytest tests/ -v
```

## System Requirements

- Python 3.11 or higher
- Linux with GNOME Keyring or KWallet (for Chrome v80+)
- D-Bus service running

## Supported Chrome Versions

| Chrome Version | Linux Support | Requirements |
|----------------|---------------|--------------|
| < v80 (pre-2020) | ✅ Full | No additional deps |
| v80-v126 | ✅ Full | `secretstorage` required |
| v127+ (App-Bound) | ⚠️ Partial | May require additional work |

## Quick Reference

```bash
# Install dependencies
pip install -e ".[linux]"

# Basic usage
browsex chrome -p "User Data" --passwords

# With verbose logging
browsex chrome -p "User Data" --passwords -v

# Multiple data types
browsex chrome -p "User Data" --passwords --bookmarks --history

# JSON output
browsex chrome -p "User Data" --all -f json > passwords.json
```

## Next Steps

After installing `secretstorage`, you should be able to decrypt passwords successfully:

```bash
browsex chrome -p "User Data" --passwords
```

Expected output:
```
[INFO] Decryption key obtained for Linux
[INFO] Successfully decrypted 42 logins

=== PASSWORDS ===

URL: https://github.com/
Username: your_username
Password: your_actual_password
...
```
