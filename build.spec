# build.spec
# ==========
# PyInstaller spec file for Encryptor.
#
# Build command (from project root):
#   pyinstaller build.spec
#
# Output: dist/Encryptor.exe  (single portable executable, no console)

import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(SPEC))   # directory containing this spec

# ── Data files to bundle ──────────────────────────────────────────────────────
datas = [
    # Bundle the assets folder so the icon is available at runtime
    (os.path.join(ROOT, "assets"), "assets"),
]

# Include any cryptography hazmat data files
datas += collect_data_files("cryptography")

# ── Hidden imports ────────────────────────────────────────────────────────────
# PyInstaller may miss some dynamically imported modules; list them explicitly.
hiddenimports = [
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "cryptography.hazmat.primitives.hashes",
    "cryptography.hazmat.backends.openssl",
    "cryptography.hazmat.backends.openssl.backend",
    "cryptography.fernet",
]
hiddenimports += collect_submodules("cryptography")

# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(
    [os.path.join(ROOT, "main.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude large, unused stdlib modules to reduce binary size
        "tkinter",
        "unittest",
        "email",
        "html",
        "http",
        "urllib",
        "xml",
        "xmlrpc",
        "pydoc",
        "doctest",
        "difflib",
        "ftplib",
        "imaplib",
        "mailbox",
        "mimetypes",
        "smtplib",
        "sqlite3",
    ],
    noarchive=False,
    optimize=1,
)

# ── PYZ archive (Python bytecode) ─────────────────────────────────────────────
pyz = PYZ(a.pure)

# ── EXE ───────────────────────────────────────────────────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Encryptor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,             # Compress with UPX if available (reduces binary size)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,        # No console window (GUI app)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Use .ico for Windows; generate from icon.png in CI
    icon=os.path.join(ROOT, "assets", "icon.ico") if sys.platform == "win32" else None,
    version=None,
    onefile=True,
)
