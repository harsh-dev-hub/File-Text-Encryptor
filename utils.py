"""
utils.py
========
Miscellaneous helper utilities for Encryptor.
"""

import os
import sys


def resource_path(relative: str) -> str:
    """
    Resolve the path to a bundled resource.

    PyInstaller extracts assets to sys._MEIPASS at runtime; during
    development we fall back to the directory containing this script.
    """
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative)


def encrypted_output_path(input_path: str) -> str:
    """Return the default output path for an encrypted file."""
    return input_path + ".enc"


def decrypted_output_path(input_path: str) -> str:
    """
    Return the default output path for a decrypted file.
    Strips the trailing '.enc' extension if present.
    """
    if input_path.endswith(".enc"):
        return input_path[:-4]
    # If it doesn't end in .enc, append '.dec' to avoid overwriting the source
    root, ext = os.path.splitext(input_path)
    return root + ".dec" + ext


def human_readable_size(num_bytes: int) -> str:
    """Convert a byte count to a human-readable string (e.g. '4.2 MB')."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def is_encrypted_file(path: str) -> bool:
    """Heuristic: check the file magic bytes to see if it's our format."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"ENCR"
    except OSError:
        return False
