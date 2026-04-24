# 🔐 Encryptor

> A modern, offline-first desktop application for secure file and text encryption.

![Build](https://img.shields.io/github/actions/workflow/status/your-org/encryptor/build.yml?style=flat-square)
![Python](https://img.shields.io/badge/python-3.11-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## ✨ Features

| Feature | Detail |
|---|---|
| **File encryption** | Drag-and-drop or file picker, `.enc` output |
| **Text encryption** | In-memory, copy-to-clipboard result |
| **Strong key derivation** | PBKDF2-HMAC-SHA256, 200 000 iterations |
| **AES encryption** | Fernet (AES-128-CBC + HMAC-SHA256) |
| **Integrity verification** | SHA-256 hash stored with ciphertext |
| **Optional compression** | zlib before encryption for smaller files |
| **Password strength** | Live indicator with 5 levels |
| **Completely offline** | No network calls, no telemetry |
| **Portable executable** | Single `.exe`, no installer needed |

---

## 🖥 Screenshot

```
┌─────────────────────────────────────────────┐
│  🔐 Encryptor   Secure offline encryption   │
├──────────────────┬──────────────────────────┤
│ 🗂 File Mode     │ 📝 Text Mode              │
│                  │                           │
│  ╔════════════╗  │  [ Input text…          ] │
│  ║  📂        ║  │  [ Output text…         ] │
│  ║ Drop here  ║  │  PASSWORD                 │
│  ╚════════════╝  │  [●●●●●●●●] 👁            │
│  PASSWORD        │  ████░░  Strong           │
│  [●●●●●] 👁      │  [🔒 Encrypt] [🔓 Decrypt]│
│  ████  Strong    │                           │
│  [🔒 Encrypt]    │                           │
│  [🔓 Decrypt]    │                           │
└──────────────────┴───────────────────────────┘
```

---

## 🚀 Quick Start

### Option A — Download the portable executable

1. Go to [Releases](../../releases) and download `Encryptor.exe`
2. Double-click to run — no installation needed

### Option B — Run from source

```bash
# Clone the repo
git clone https://github.com/your-org/encryptor.git
cd encryptor

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # Linux / macOS

# Install dependencies
pip install -r requirements.txt

# Launch
python main.py
```

### Option C — Build the executable locally

```bash
pip install -r requirements.txt
pyinstaller build.spec --clean --noconfirm
# Output: dist/Encryptor.exe
```

---

## 🔐 Security Details

### Key Derivation
```
password + salt (16 random bytes)
        │
        ▼
PBKDF2-HMAC-SHA256  (200 000 iterations)
        │
        ▼
32-byte key  →  URL-safe Base64  →  Fernet key
```

### Encrypted File Format
```
Offset  Size  Field
──────  ────  ──────────────────────────────────
     0     4  Magic bytes: b"ENCR"
     4     1  Version (1)
     5     1  Flags  (bit 0 = compressed)
     6    16  Random salt
    22    32  SHA-256 hash of original plaintext
    54     4  Ciphertext length (uint32 LE)
    58     N  Fernet ciphertext (AES-CBC + HMAC)
```

### Why Fernet?
Fernet is a symmetric encryption recipe from the `cryptography` library. It
guarantees:
- Confidentiality via **AES-128-CBC**
- Authenticity and integrity via **HMAC-SHA256**
- Timestamp-based freshness (unused here but provides future flexibility)

---

## 📁 Project Structure

```
encryptor/
├── main.py          # Entry point, QApplication setup
├── ui.py            # All PySide6 widgets and layout
├── crypto_core.py   # Encryption / decryption logic (no UI dependency)
├── utils.py         # Path helpers, size formatting, magic-byte detection
├── requirements.txt # Python dependencies
├── build.spec       # PyInstaller configuration
├── README.md
├── assets/
│   └── icon.png     # Application icon (replace with your own)
└── .github/
    └── workflows/
        └── build.yml  # GitHub Actions CI/CD
```

---

## ⚙️ GitHub Actions CI

Every push triggers an automatic Windows build:

1. **Checkout** source code
2. **Install** Python 3.11 and dependencies
3. **Convert** `assets/icon.png` → `assets/icon.ico`
4. **Run** `pyinstaller build.spec`
5. **Upload** `dist/Encryptor.exe` as a workflow artifact (30-day retention)
6. **Create a GitHub Release** with the `.exe` attached (tag pushes only)

To publish a release:
```bash
git tag v1.2.0
git push origin v1.2.0
```

---

## 🛡 Error Handling

| Situation | User message |
|---|---|
| Wrong password | "Decryption failed. The password is incorrect…" |
| Tampered file | "Integrity check failed. The file may have been tampered with." |
| File too large | "File exceeds maximum allowed size of 100 MB." |
| Empty password | "Please enter a password." |
| Corrupt format | "Not a valid Encryptor file (bad magic bytes)." |

---

## 📜 License

MIT — see [LICENSE](LICENSE) for details.
