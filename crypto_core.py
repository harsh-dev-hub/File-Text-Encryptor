"""
crypto_core.py
==============
Core cryptographic operations for the Encryptor application.

Security design:
  - PBKDF2-HMAC-SHA256 with 200,000 iterations for key derivation
  - AES-128 via Fernet (which uses AES-CBC + HMAC-SHA256 internally)
  - 16-byte cryptographically random salt per encryption
  - SHA-256 integrity hash stored alongside ciphertext
  - Optional zlib compression before encryption (reduces size for text files)
"""

import os
import hashlib
import struct
import zlib
from base64 import urlsafe_b64encode

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ── Constants ──────────────────────────────────────────────────────────────────
MAGIC = b"ENCR"          # 4-byte file magic to identify our format
VERSION = 1              # Format version byte
SALT_SIZE = 16           # Bytes of random salt
ITERATIONS = 200_000     # PBKDF2 iteration count
MAX_FILE_BYTES = 100 * 1024 * 1024   # 100 MB hard limit
COMPRESS_FLAG = 0x01     # Bit flag: data was compressed before encryption


# ── Key Derivation ─────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from a password and salt using PBKDF2-HMAC-SHA256.
    Returns URL-safe base64 encoded key suitable for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    raw_key = kdf.derive(password.encode("utf-8"))
    # Fernet requires a URL-safe base64 encoded 32-byte key
    return urlsafe_b64encode(raw_key)


# ── Binary Format ──────────────────────────────────────────────────────────────
#
# Encrypted file layout (all fields little-endian unless noted):
#
#  Offset  Size  Field
#  ------  ----  --------------------------------------------------------
#       0     4  Magic: b"ENCR"
#       4     1  Version (currently 1)
#       5     1  Flags  (COMPRESS_FLAG = 0x01)
#       6    16  Salt (random bytes)
#      22    32  SHA-256 hash of the plaintext (for integrity verification)
#      54     4  Length of the following Fernet ciphertext (uint32 LE)
#      58     N  Fernet ciphertext
#
# ──────────────────────────────────────────────────────────────────────────────

HEADER_SALT_OFFSET = 6
HEADER_HASH_OFFSET = HEADER_SALT_OFFSET + SALT_SIZE        # 22
HEADER_CTLEN_OFFSET = HEADER_HASH_OFFSET + 32              # 54
HEADER_CT_OFFSET = HEADER_CTLEN_OFFSET + 4                 # 58


def _build_header(salt: bytes, plaintext_hash: bytes, flags: int) -> bytes:
    """Pack the fixed-size header fields."""
    return (
        MAGIC
        + bytes([VERSION, flags])
        + salt
        + plaintext_hash
    )


def _parse_header(data: bytes) -> tuple[int, bytes, bytes]:
    """
    Parse header from raw bytes.
    Returns (flags, salt, plaintext_hash).
    Raises ValueError on bad magic/version.
    """
    if len(data) < HEADER_CT_OFFSET:
        raise ValueError("File is too short to be a valid encrypted file.")
    if data[:4] != MAGIC:
        raise ValueError("Not a valid Encryptor file (bad magic bytes).")
    if data[4] != VERSION:
        raise ValueError(f"Unsupported file version: {data[4]}.")
    flags = data[5]
    salt = data[HEADER_SALT_OFFSET: HEADER_HASH_OFFSET]
    plaintext_hash = data[HEADER_HASH_OFFSET: HEADER_CTLEN_OFFSET]
    return flags, salt, plaintext_hash


# ── File Encryption / Decryption ───────────────────────────────────────────────

def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    compress: bool = True,
    progress_callback=None,
) -> None:
    """
    Encrypt a file from input_path and write ciphertext to output_path.

    Parameters
    ----------
    input_path      : path to the plaintext file
    output_path     : path for the encrypted output (.enc)
    password        : user-supplied password string
    compress        : if True, zlib-compress plaintext before encryption
    progress_callback : optional callable(percent: int) for UI updates
    """
    if not password:
        raise ValueError("Password must not be empty.")

    file_size = os.path.getsize(input_path)
    if file_size > MAX_FILE_BYTES:
        raise ValueError(f"File exceeds maximum allowed size of 100 MB.")

    # Read plaintext
    with open(input_path, "rb") as f:
        plaintext = f.read()

    if progress_callback:
        progress_callback(10)

    # Compute integrity hash of original plaintext
    plaintext_hash = hashlib.sha256(plaintext).digest()

    # Optional compression
    flags = 0
    payload = plaintext
    if compress:
        compressed = zlib.compress(plaintext, level=6)
        if len(compressed) < len(plaintext):   # Only use if it actually helps
            payload = compressed
            flags |= COMPRESS_FLAG

    if progress_callback:
        progress_callback(25)

    # Derive key with fresh random salt
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    if progress_callback:
        progress_callback(40)

    # Encrypt
    ciphertext = fernet.encrypt(payload)

    if progress_callback:
        progress_callback(80)

    # Assemble output: header + 4-byte ciphertext length + ciphertext
    header = _build_header(salt, plaintext_hash, flags)
    ct_len = struct.pack("<I", len(ciphertext))

    with open(output_path, "wb") as f:
        f.write(header + ct_len + ciphertext)

    if progress_callback:
        progress_callback(100)


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    progress_callback=None,
) -> None:
    """
    Decrypt a file produced by encrypt_file().

    Raises
    ------
    ValueError      : wrong password, tampered data, or format errors
    """
    if not password:
        raise ValueError("Password must not be empty.")

    with open(input_path, "rb") as f:
        data = f.read()

    if progress_callback:
        progress_callback(10)

    # Parse header
    flags, salt, stored_hash = _parse_header(data)

    # Read ciphertext length and ciphertext
    ct_len = struct.unpack("<I", data[HEADER_CTLEN_OFFSET: HEADER_CT_OFFSET])[0]
    ciphertext = data[HEADER_CT_OFFSET: HEADER_CT_OFFSET + ct_len]

    if len(ciphertext) != ct_len:
        raise ValueError("File is truncated or corrupted.")

    if progress_callback:
        progress_callback(30)

    # Derive key and attempt decryption
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        payload = fernet.decrypt(ciphertext)
    except InvalidToken:
        raise ValueError(
            "Decryption failed. The password is incorrect or the file has been tampered with."
        )

    if progress_callback:
        progress_callback(70)

    # Decompress if needed
    if flags & COMPRESS_FLAG:
        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            raise ValueError("Decompression failed. File may be corrupted.")

    # Verify integrity hash
    actual_hash = hashlib.sha256(payload).digest()
    if actual_hash != stored_hash:
        raise ValueError(
            "Integrity check failed. The decrypted data does not match the original. "
            "The file may have been tampered with."
        )

    if progress_callback:
        progress_callback(90)

    with open(output_path, "wb") as f:
        f.write(payload)

    if progress_callback:
        progress_callback(100)


# ── Text Encryption / Decryption ───────────────────────────────────────────────

def encrypt_text(plaintext: str, password: str) -> str:
    """
    Encrypt a UTF-8 string and return a base64-encoded token string.

    The token format is:  <base64(salt)>$<fernet_token>
    Both parts are URL-safe and can be safely copied as text.
    """
    if not password:
        raise ValueError("Password must not be empty.")
    if not plaintext:
        raise ValueError("Input text must not be empty.")

    raw = plaintext.encode("utf-8")
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    token = fernet.encrypt(raw)

    # Encode salt and token together as a single transferable string
    salt_b64 = urlsafe_b64encode(salt).decode("ascii")
    token_str = token.decode("ascii")
    return f"{salt_b64}${token_str}"


def decrypt_text(cipher_str: str, password: str) -> str:
    """
    Decrypt a string produced by encrypt_text().

    Raises ValueError on wrong password or malformed input.
    """
    if not password:
        raise ValueError("Password must not be empty.")
    if not cipher_str.strip():
        raise ValueError("Encrypted text must not be empty.")

    try:
        salt_b64, token_str = cipher_str.strip().split("$", 1)
        from base64 import urlsafe_b64decode
        salt = urlsafe_b64decode(salt_b64.encode("ascii"))
        token = token_str.encode("ascii")
    except Exception:
        raise ValueError("Invalid encrypted text format.")

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        raw = fernet.decrypt(token)
    except InvalidToken:
        raise ValueError(
            "Decryption failed. The password is incorrect or the text has been tampered with."
        )

    return raw.decode("utf-8")


# ── Password Strength ──────────────────────────────────────────────────────────

def password_strength(password: str) -> tuple[int, str]:
    """
    Return (score 0-4, label) for a password.

    Score thresholds:
      0  Very Weak
      1  Weak
      2  Fair
      3  Strong
      4  Very Strong
    """
    if not password:
        return 0, "No password"

    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 14:
        score += 1
    if any(c.isupper() for c in password) and any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 0.5
    if any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        score += 0.5

    score = min(int(score), 4)
    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    return score, labels[score]
