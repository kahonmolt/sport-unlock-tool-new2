"""AES-256-CTR firmware crypto primitives for Simagic ``.sfu`` packages.

The key and counter IV are fleet constants extracted from ``simpro.exe``
(RVA 0x12C8730 / 0x12C8750).  CTR is symmetric and position based, so the
same function both decrypts and encrypts the payload that starts at file
offset 0x40.

See FINDINGS.md sections 2-3 for the full derivation.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#: simpro.exe RVA 0x12C8730, 32 bytes.
AES_KEY = bytes.fromhex(
    "2037df2888ab45f7841178e25d25998c"
    "99aa34774383ee922234129833833284"
)
#: simpro.exe RVA 0x12C8750, 16 bytes, big-endian counter.
IV_COUNTER = bytes.fromhex("343413991235ddf3393899a1aa843299")

KEY_HEX = AES_KEY.hex()
IV_HEX = IV_COUNTER.hex()

BLOCK_SIZE = 16

#: Digest candidates tried by :func:`detect_digest`, in priority order.
DIGEST_ALGORITHMS = ("sha1", "sha256")


def crypt(buf: bytes, key: bytes = AES_KEY, iv: bytes = IV_COUNTER) -> bytes:
    """XOR ``buf`` with the AES-256-CTR keystream starting at ``iv``.

    ``buf`` must be the payload region only (file offset 0x40 onwards); the
    counter starts at ``iv`` for the first byte of ``buf``.
    """
    if not buf:
        return b""
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    counter = int.from_bytes(iv, "big")
    out = bytearray(len(buf))
    for block in range(0, len(buf), BLOCK_SIZE):
        keystream = ecb.update((counter + block // BLOCK_SIZE).to_bytes(16, "big"))
        chunk = buf[block:block + BLOCK_SIZE]
        for i, byte in enumerate(chunk):
            out[block + i] = byte ^ keystream[i]
    return bytes(out)


# Explicit alias: CTR encryption and decryption are the same operation.
encrypt = crypt
decrypt = crypt


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_digest(data: bytes, algorithm: str) -> bytes:
    """Return the full digest for ``algorithm`` (``sha1`` or ``sha256``)."""
    algorithm = algorithm.lower().replace("-", "")
    if algorithm not in DIGEST_ALGORITHMS:
        raise ValueError("unsupported digest algorithm: %r" % (algorithm,))
    return hashlib.new(algorithm, data).digest()


def digest_matches(stored: bytes, data: bytes, algorithm: str) -> bool:
    """True when ``stored`` is a truncation of the digest of ``data``."""
    if not stored:
        return False
    digest = compute_digest(data, algorithm)
    return digest[:len(stored)] == stored


def detect_digest(
    stored: bytes,
    candidates: dict[str, bytes],
    algorithms: tuple[str, ...] = DIGEST_ALGORITHMS,
) -> Optional[tuple[str, str]]:
    """Match ``stored`` against digests of named candidate byte ranges.

    ``candidates`` maps a human-readable range name (for example
    ``"encrypted_payload"``) to the bytes that range covers.  Returns
    ``(algorithm, range_name)`` for the first match, otherwise ``None``.
    """
    if not stored:
        return None
    for algorithm in algorithms:
        for name, data in candidates.items():
            if digest_matches(stored, data, algorithm):
                return algorithm, name
    return None
