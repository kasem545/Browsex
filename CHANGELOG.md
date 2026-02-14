# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-02-14

### Added
- **Project renamed from `browspass` to `browsex`** for better branding
- **Output file support**: New `-o/--output FILE` flag to save results to file instead of stdout
- **Cross-platform DPAPI decryption**: Decrypt Windows Chrome profiles on Linux/macOS using masterkeys
  - New `-k/--masterkey HEX` flag for all Chromium browsers (Chrome, Brave, Edge, Opera)
  - Integrated `dpapick3` for offline DPAPI blob decryption
  - Comprehensive documentation in `CROSS_PLATFORM_DPAPI.md`
- **Intelligent file discovery**: Automatically find browser files regardless of directory structure
  - Recursive search up to 3 levels deep
  - Smart Local State detection (checks parent/grandparent directories)
  - Profile directory auto-detection
- **Multiple data extraction modes**:
  - `--passwords`: Extract saved passwords
  - `--bookmarks`: Extract bookmarks
  - `--history`: Extract browsing history
  - `--all`: Extract all data types
- **Three output formats**: text, JSON, CSV

### Changed
- **BREAKING**: Chromium browsers (Chrome, Brave, Edge, Opera) now **require** `-k/--masterkey` flag for password extraction
  - Bookmarks and history do NOT require `-k` flag
  - This enforces explicit masterkey usage for password decryption
- **BREAKING**: Removed default `--passwords` behavior - must explicitly specify data type flags
  - Users must specify at least one of: `--passwords`, `--bookmarks`, `--history`, or `--all`
  - This prevents accidental password extraction without proper flags

### Security
- Enhanced security by requiring explicit `-k` flag for password decryption
- Prevents users from attempting password extraction without required masterkey
- Clear error messages guide users to provide `-k` when needed

### Documentation
- **README.md**: Updated with masterkey requirements and clear warnings
- **QUICKSTART.md**: Comprehensive examples with -k flag usage
- **CROSS_PLATFORM_DPAPI.md**: 7 methods to extract DPAPI masterkeys from Windows
- **INSTALL_LINUX.md**: Linux-specific installation and troubleshooting

### Fixed
- Type hints: 100% mypy strict compliance
- All ruff checks passing
- 27/27 tests passing

## Migration Guide

### From browspass to browsex

**Command Changes**:
```bash
# OLD (browspass)
browspass chrome -p /path

# NEW (browsex - requires explicit flag + masterkey for passwords)
browsex chrome -p /path --passwords -k <masterkey>

# OR for bookmarks only (no -k needed)
browsex chrome -p /path --bookmarks
```

**Import Changes**:
```python
# OLD
from browspass.browsers import Chrome

# NEW
from browsex.browsers import Chrome
```

### Password Extraction Requirements

**Before (v0.x)**:
```bash
# This used to work (attempted password extraction by default)
browsex chrome -p /path
```

**After (v1.0.0)**:
```bash
# ERROR: No data type specified
browsex chrome -p /path

# ERROR: Chrome password extraction requires -k flag
browsex chrome -p /path --passwords

# CORRECT: Explicit flag + masterkey
browsex chrome -p /path --passwords -k <64_byte_hex_masterkey>

# CORRECT: Bookmarks without masterkey
browsex chrome -p /path --bookmarks
```

### Why These Changes?

1. **Explicit is better than implicit**: Users must consciously choose what to extract
2. **Security**: Prevents accidental password extraction without proper keys
3. **Clarity**: Clear error messages guide users to correct usage
4. **Cross-platform**: Enforces masterkey for Windows profiles on Linux/macOS

## [0.1.0] - Initial Release (Pre-rename)

- Basic Chrome/Firefox password extraction
- Local-only decryption (same machine)
- Limited file discovery
- Implicit password extraction (no flag required)
