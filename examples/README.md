# Browsex Examples

This directory contains example scripts demonstrating programmatic usage of the browsex library.

## Available Examples

### 1. `basic_usage.py`
Simple example showing how to extract passwords from Firefox and Chrome programmatically.

**Usage**:
```bash
python examples/basic_usage.py
```

**Features**:
- Firefox password extraction
- Chrome password extraction
- Basic error handling

### 2. `advanced_usage.py`
Comprehensive examples covering all major features.

**Usage**:
```bash
python examples/advanced_usage.py
```

**Features**:
- Multiple output formats (JSON, CSV)
- Extract from all browsers
- Save data to files
- Cross-platform Windows profile decryption (example code)

## Running Examples

### Install browsex first:
```bash
cd ..
uv pip install -e ".[linux,crossplatform]"
```

### Run examples:
```bash
# Basic usage
python examples/basic_usage.py

# Advanced usage
python examples/advanced_usage.py
```

## Modifying Examples

### Update profile paths
Edit the Path strings to match your system:

```python
# Linux
profile = Path.home() / ".config/google-chrome/Default"

# macOS
profile = Path.home() / "Library/Application Support/Google/Chrome/Default"

# Windows
profile = Path(r"C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default")
```

### Add error handling
```python
try:
    chrome = Chrome(profile_path)
    logins = chrome.extract_logins()
except FileNotFoundError:
    print("Profile not found")
except Exception as e:
    print(f"Error: {e}")
```

### Filter results
```python
# Only show passwords for specific domain
logins = chrome.extract_logins()
github_logins = [l for l in logins if "github.com" in l.origin_url]
```

## API Reference

### Browser Classes

All browsers follow the same interface:

```python
from browsex.browsers import Chrome, Brave, Edge, Opera, FirefoxDecryptor

# Chromium browsers
chrome = Chrome(profile_path, masterkey_hex=None)
brave = Brave(profile_path, masterkey_hex=None)
edge = Edge(profile_path, masterkey_hex=None)
opera = Opera(profile_path, masterkey_hex=None)

# Firefox (requires master password if set)
firefox = FirefoxDecryptor(profile_path, master_password="")
```

### Extraction Methods

```python
# Extract passwords
logins = browser.extract_logins()  # Returns list[LoginEntry]

# Extract bookmarks
bookmarks = browser.extract_bookmarks()  # Returns list[BookmarkEntry]

# Extract history
history = browser.extract_history()  # Returns list[HistoryEntry]
```

### Data Models

```python
# LoginEntry
login.origin_url       # str: Website URL
login.username         # str: Username/email
login.password         # str: Decrypted password
login.date_created     # int | None: Chrome timestamp
login.times_used       # int | None: Usage count

# BookmarkEntry
bookmark.url           # str: Bookmark URL
bookmark.title         # str | None: Bookmark title
bookmark.date_added    # int | None: Chrome timestamp
bookmark.folder        # str | None: Folder path

# HistoryEntry
entry.url              # str: Visited URL
entry.title            # str | None: Page title
entry.visit_count      # int | None: Visit count
entry.last_visit_time  # int | None: Chrome timestamp
```

### Convert to Dictionary

```python
# All data models have .to_dict() method
login_dict = login.to_dict()
# {
#   "origin_url": "https://github.com",
#   "username": "user@example.com",
#   "password": "secret123",
#   "date_created": 13324567890000000,
#   "times_used": 5
# }
```

## Common Patterns

### Extract all data types
```python
chrome = Chrome(profile_path)

logins = chrome.extract_logins()
bookmarks = chrome.extract_bookmarks()
history = chrome.extract_history()

print(f"Found:")
print(f"  - {len(logins)} passwords")
print(f"  - {len(bookmarks)} bookmarks")
print(f"  - {len(history)} history entries")
```

### Save as JSON
```python
import json

logins = chrome.extract_logins()
data = [login.to_dict() for login in logins]

with open("passwords.json", "w") as f:
    json.dump(data, f, indent=2)
```

### Save as CSV
```python
import csv

logins = chrome.extract_logins()

with open("passwords.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["origin_url", "username", "password"])
    writer.writeheader()
    for login in logins:
        writer.writerow(login.to_dict())
```

### Cross-platform decryption
```python
# Decrypt Windows Chrome profile on Linux
masterkey = "1a2b3c4d5e6f..."  # 128 hex chars from mimikatz

chrome = Chrome(windows_profile_path, masterkey_hex=masterkey)
logins = chrome.extract_logins()
```

## Security Notes

⚠️ **These examples output plaintext passwords**

- Use in secure environments only
- Don't log passwords to console in production
- Delete output files after use
- Only use on YOUR OWN devices or with authorization

## Further Reading

- [README.md](../README.md) - Main documentation
- [QUICKSTART.md](../QUICKSTART.md) - CLI usage guide
- [CROSS_PLATFORM_DPAPI.md](../CROSS_PLATFORM_DPAPI.md) - DPAPI masterkey extraction
- [DEVELOPMENT.md](../DEVELOPMENT.md) - Architecture and development guide
