"""Digest validation and re-signing for Simagic ``.sfu`` packages.

The 20-byte field at decrypted offset 0x4C is a digest of currently unknown
construction (FINDINGS.md section 6.5).  Earlier analysis ruled out plain
SHA-1/SHA-256 over the usual ranges, MD5, SHA-512, HMAC and AES-CMAC, so this
module does not assume an algorithm: it first *validates* a candidate spec
against the stock package and only then uses it to re-sign a patched image.

Detection order follows the design brief: SHA-1 of the encrypted payload
(from 0x100) first, then SHA-256, then the safe plaintext coverages.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from utils import crypto, sfu

ALGORITHMS = ("sha1", "sha256")

#: Coverage names and their file offsets.  Coverages that include the digest
#: field itself are intentionally absent: a digest of its own ciphertext has
#: no fixed point and therefore cannot be re-signed.
COVERAGES: dict[str, int] = {
    "encrypted_payload": 0x100,
    "plain_payload": 0x100,
    "plain_image": sfu.IMAGE_OFFSET,
}

DETECTION_ORDER: tuple[tuple[str, str], ...] = (
    ("sha1", "encrypted_payload"),
    ("sha256", "encrypted_payload"),
    ("sha1", "plain_payload"),
    ("sha256", "plain_payload"),
    ("sha1", "plain_image"),
    ("sha256", "plain_image"),
)


class SignatureError(Exception):
    """Raised when a signature/digest operation cannot be performed safely."""


@dataclass(frozen=True)
class SignatureSpec:
    algorithm: str
    coverage: str

    def __post_init__(self) -> None:
        if self.algorithm not in ALGORITHMS:
            raise SignatureError("unsupported digest algorithm: %r" % (self.algorithm,))
        if self.coverage not in COVERAGES:
            raise SignatureError("unsupported digest coverage: %r" % (self.coverage,))

    @property
    def label(self) -> str:
        return "%s(%s)" % (self.algorithm, self.coverage)

    def as_dict(self) -> dict[str, str]:
        return {"algorithm": self.algorithm, "coverage": self.coverage}


def parse_spec(algorithm: str, coverage: str = "encrypted_payload") -> SignatureSpec:
    return SignatureSpec(
        algorithm=algorithm.lower().replace("-", ""),
        coverage=coverage.lower().replace("-", "_"),
    )


def _coverage_bytes(
    coverage: str,
    sfu_bytes: bytes,
    decrypted: "sfu.DecryptedSFU",
) -> bytes:
    if coverage.startswith("encrypted"):
        start = COVERAGES[coverage]
        return sfu_bytes[start:]
    if coverage == "plain_payload":
        return decrypted.full_bytes[COVERAGES[coverage]:]
    if coverage == "plain_image":
        return decrypted.image
    raise SignatureError("unknown coverage: %r" % (coverage,))


def compute(
    spec: SignatureSpec,
    sfu_bytes: bytes,
    decrypted: "sfu.DecryptedSFU",
) -> bytes:
    data = _coverage_bytes(spec.coverage, sfu_bytes, decrypted)
    return crypto.compute_digest(data, spec.algorithm)[:sfu.DIGEST_SIZE]


def detect(
    sfu_bytes: bytes,
    decrypted: "sfu.DecryptedSFU",
    order: Sequence[tuple[str, str]] = DETECTION_ORDER,
) -> Optional[SignatureSpec]:
    """Return the spec that reproduces the stored digest, else ``None``."""
    stored = decrypted.digest
    if not stored or stored == b"\x00" * sfu.DIGEST_SIZE:
        return None
    for algorithm, coverage in order:
        spec = SignatureSpec(algorithm, coverage)
        try:
            if compute(spec, sfu_bytes, decrypted) == stored:
                return spec
        except SignatureError:
            continue
    return None


def resign(
    decrypted: "sfu.DecryptedSFU",
    spec: SignatureSpec,
    verify: bool = True,
) -> tuple[bytes, bytes]:
    """Return ``(sfu_bytes, digest)`` with the digest recomputed per ``spec``.

    Raises :class:`SignatureError` if the coverage is self-referential (the
    digest would not reach a fixed point) or if verification fails.
    """
    base = decrypted.to_sfu_bytes()
    digest = compute(spec, base, decrypted)
    updated = decrypted.with_digest(digest)
    result = updated.to_sfu_bytes()

    if verify:
        check = compute(spec, result, updated)
        if check != digest:
            raise SignatureError(
                "signature coverage %r is self-referential; cannot re-sign"
                % (spec.coverage,)
            )
    return result, digest


def keep_digest(decrypted: "sfu.DecryptedSFU") -> bytes:
    """Return the package with the original digest untouched."""
    return decrypted.to_sfu_bytes()


def describe(sfu_bytes: bytes, decrypted: "sfu.DecryptedSFU") -> dict[str, object]:
    spec = detect(sfu_bytes, decrypted)
    return {
        "stored_digest": decrypted.digest.hex(),
        "validated": spec is not None,
        "spec": spec.as_dict() if spec else None,
        "label": spec.label if spec else "unknown (not reproducible)",
        "tried": [
            {"algorithm": algorithm, "coverage": coverage}
            for algorithm, coverage in DETECTION_ORDER
        ],
    }
