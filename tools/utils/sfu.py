"""Parser and assembler for the Simagic ``.sfu`` firmware container.

Measured layout (FINDINGS.md section 2 and 4)::

    0x000  64      header (magic, device, version, UUIDs, PID/VID)
    0x040  var     AES-256-CTR ciphertext of everything below
                   -- decrypted view --
    0x040  8       signature-absent marker (0xFF x 8)
    0x048  4       image length (little endian, = file_size - 0x240)
    0x04C  20      digest / signature block (construction unknown)
    0x060  0x1E0   padding, 0xFF
    0x240  var     Cortex-M flash image

The ciphertext starts at 0x40, not 0x100.  Re-encrypting the decrypted body
with the same key/IV reproduces the original file byte-for-byte.
"""
from __future__ import annotations

import datetime as _datetime
import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import crypto

SFU_MAGIC = b"SIMPROSFU100"
HEADER_LEN = 0x40
BODY_OFFSET = 0x40
RECORD_OFFSET = 0x40
LENGTH_OFFSET = 0x48
DIGEST_OFFSET = 0x4C
DIGEST_SIZE = 20
PADDING_OFFSET = 0x60
IMAGE_OFFSET = 0x240
IMAGE_ALIGN = 0x100


class SFUError(Exception):
    """Raised when a file is not a valid SIMPROSFU package."""


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("latin-1", "replace")


def _json_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Header:
    magic: str
    header_len: int
    device: str
    version: str
    blob_len: int
    product_uuid: int
    board_uuid: int
    pid: int
    vid: int
    raw: bytes

    @classmethod
    def parse(cls, raw: bytes) -> "Header":
        if len(raw) < HEADER_LEN:
            raise SFUError("header is shorter than %d bytes" % HEADER_LEN)
        if raw[:12] != SFU_MAGIC:
            raise SFUError("not a SIMPROSFU package (bad magic)")
        return cls(
            magic=_cstr(raw[0x00:0x0C]),
            header_len=struct.unpack_from("<H", raw, 0x0E)[0],
            device=_cstr(raw[0x10:0x20]),
            version=_cstr(raw[0x20:0x30]),
            blob_len=struct.unpack_from("<I", raw, 0x30)[0],
            product_uuid=struct.unpack_from("<I", raw, 0x34)[0],
            board_uuid=struct.unpack_from("<I", raw, 0x38)[0],
            pid=struct.unpack_from("<H", raw, 0x3C)[0],
            vid=struct.unpack_from("<H", raw, 0x3E)[0],
            raw=bytes(raw[:HEADER_LEN]),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "magic": self.magic,
            "header_len": self.header_len,
            "device": self.device,
            "version": self.version,
            "blob_len": self.blob_len,
            "product_uuid": "0x%08X" % self.product_uuid,
            "board_uuid": "0x%08X" % self.board_uuid,
            "pid": "0x%04X" % self.pid,
            "vid": "0x%04X" % self.vid,
        }


@dataclass
class DecryptedSFU:
    """Decrypted view of an SFU: header plus plaintext body (file 0x40..EOF)."""

    header: Header
    body: bytes

    # ------------------------------------------------------------------ parse
    @classmethod
    def from_sfu_bytes(cls, raw: bytes) -> "DecryptedSFU":
        parsed = SFU.from_bytes(raw)
        return parsed.decrypt()

    @classmethod
    def from_decrypted_bytes(cls, raw: bytes) -> "DecryptedSFU":
        header = Header.parse(raw[:HEADER_LEN])
        return cls(header=header, body=bytes(raw[BODY_OFFSET:]))

    @classmethod
    def from_file(cls, path: "str | Path") -> "DecryptedSFU":
        sfu = SFU.from_file(path)
        return sfu.decrypt()

    # --------------------------------------------------------------- records
    @property
    def marker(self) -> bytes:
        return self.body[0x00:0x08]

    @property
    def image_length(self) -> int:
        return struct.unpack_from("<I", self.body, LENGTH_OFFSET - BODY_OFFSET)[0]

    @property
    def digest(self) -> bytes:
        start = DIGEST_OFFSET - BODY_OFFSET
        return self.body[start:start + DIGEST_SIZE]

    @property
    def image(self) -> bytes:
        return self.body[IMAGE_OFFSET - BODY_OFFSET:]

    @property
    def padding(self) -> bytes:
        return self.body[PADDING_OFFSET - BODY_OFFSET:IMAGE_OFFSET - BODY_OFFSET]

    @property
    def full_bytes(self) -> bytes:
        """Header + plaintext body, i.e. the decrypted file on disk."""
        return self.header.raw + self.body

    # ---------------------------------------------------------------- checks
    def record_ok(self) -> bool:
        return (
            self.marker == b"\xFF" * 8
            and self.image_length == len(self.image)
            and set(self.padding) <= {0xFF}
        )

    def image_sha256(self) -> str:
        return _json_sha256(self.image)

    # ------------------------------------------------------------- mutation
    def with_digest(self, digest: bytes) -> "DecryptedSFU":
        if len(digest) != DIGEST_SIZE:
            raise ValueError("digest must be exactly %d bytes" % DIGEST_SIZE)
        body = bytearray(self.body)
        start = DIGEST_OFFSET - BODY_OFFSET
        body[start:start + DIGEST_SIZE] = digest
        return DecryptedSFU(header=self.header, body=bytes(body))

    def with_image(self, image: bytes) -> "DecryptedSFU":
        expected = self.image_length
        if len(image) != expected:
            raise ValueError(
                "replacement image must keep length %d (got %d)"
                % (expected, len(image))
            )
        body = bytearray(self.body)
        start = IMAGE_OFFSET - BODY_OFFSET
        body[start:start + len(image)] = image
        return DecryptedSFU(header=self.header, body=bytes(body))

    def replace_bytes(self, offset: int, replacement: bytes) -> "DecryptedSFU":
        """Return a copy with ``replacement`` written at file-relative ``offset``."""
        if offset < BODY_OFFSET:
            raise ValueError("offsets inside the 64-byte header are not patchable")
        if offset + len(replacement) > len(self.header.raw) + len(self.body):
            raise ValueError("replacement runs past end of file")
        body = bytearray(self.body)
        start = offset - BODY_OFFSET
        body[start:start + len(replacement)] = replacement
        return DecryptedSFU(header=self.header, body=bytes(body))

    # --------------------------------------------------------------- encrypt
    def to_sfu_bytes(self) -> bytes:
        return self.header.raw + crypto.crypt(self.body)

    def write_sfu(self, path: "str | Path") -> None:
        Path(path).write_bytes(self.to_sfu_bytes())

    def write_decrypted(self, path: "str | Path") -> None:
        Path(path).write_bytes(self.full_bytes)

    def write_image(self, path: "str | Path") -> None:
        Path(path).write_bytes(self.image)

    # ---------------------------------------------------------------- report
    def describe(self) -> dict[str, Any]:
        vt = find_vector_table(self.image)
        return {
            "header": self.header.as_dict(),
            "file_size": HEADER_LEN + len(self.body),
            "record": {
                "marker": self.marker.hex(),
                "image_length": self.image_length,
                "digest": self.digest.hex(),
                "record_ok": self.record_ok(),
            },
            "image": {
                "offset": "0x%X" % IMAGE_OFFSET,
                "size": len(self.image),
                "sha256": self.image_sha256(),
                "vector_table": vt,
            },
        }


@dataclass
class SFU:
    """Encrypted SFU package as stored on disk."""

    header: Header
    ciphertext: bytes
    raw: bytes = field(repr=False, default=b"")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SFU":
        if len(raw) < HEADER_LEN:
            raise SFUError("file is too small to be an SFU package")
        header = Header.parse(raw[:HEADER_LEN])
        if header.header_len != HEADER_LEN:
            raise SFUError(
                "unsupported header length 0x%X (expected 0x40)"
                % header.header_len
            )
        body = raw[BODY_OFFSET:]
        expected = header.blob_len
        if expected != len(body):
            raise SFUError(
                "header blob length 0x%X does not match file body 0x%X"
                % (expected, len(body))
            )
        if len(raw) != HEADER_LEN + expected:
            raise SFUError("trailing bytes after declared payload")
        return cls(header=header, ciphertext=body, raw=bytes(raw))

    @classmethod
    def from_file(cls, path: "str | Path") -> "SFU":
        return cls.from_bytes(Path(path).read_bytes())

    def decrypt(self) -> DecryptedSFU:
        return DecryptedSFU(
            header=self.header,
            body=crypto.crypt(self.ciphertext),
        )

    @property
    def sha256(self) -> str:
        return _json_sha256(self.raw)


def find_vector_table(image: bytes, limit: int = 0x20000) -> Optional[dict[str, Any]]:
    """Locate a Cortex-M vector table (SP + reset handler) in ``image``."""
    for offset in range(0, min(len(image) - 16, limit), 4):
        sp, reset = struct.unpack_from("<II", image, offset)
        if (
            0x20000000 <= sp < 0x20100000
            and sp & 3 == 0
            and reset & 1
            and 0x08000000 <= reset < 0x08200000
        ):
            return {
                "offset": "0x%X" % offset,
                "initial_sp": "0x%08X" % sp,
                "reset_handler": "0x%08X" % reset,
            }
    return None


def parse_image_length(raw: bytes) -> int:
    return struct.unpack_from("<I", raw, LENGTH_OFFSET)[0]


def now_iso() -> str:
    return _datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def dump_json(path: "str | Path", payload: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
