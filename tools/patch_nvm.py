"""Locate and patch the torque limit inside a decrypted firmware image.

The Alpha Evo firmware is model-agnostic: the same image serves the 9 Nm
Sport and the 12-21 Nm Pro models, and ``max_torque`` is normally a per-unit
NVM value rather than a constant (FINDINGS_READONLY.md sections 1 and 6).
This module therefore *searches* for candidate encodings, scores them using
context, and refuses to guess when no unique candidate exists.

Supported encodings cover the possibilities left open by the design spec:
signed/unsigned 8/16/32-bit integers, IEEE-754 float32/float64, and scaled
integers (value x 10 / x 100).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from utils import sfu

#: Model-name table inside the image (FINDINGS_READONLY.md section 2).
MODEL_TABLE_OFFSET = 0x282BC
AES_SBOX_OFFSET = 0x286D8

#: Torque ratings used by the product line.
KNOWN_TORQUES = (8, 9, 10, 11, 12, 15, 18, 21)


class PatchError(Exception):
    """Raised when a patch cannot be applied safely."""


@dataclass(frozen=True)
class Encoding:
    name: str
    size: int
    struct_fmt: str
    scale: float = 1.0

    def encode(self, value: float) -> bytes:
        if self.struct_fmt[-1] in "fd":
            return struct.pack("<" + self.struct_fmt, float(value))
        return struct.pack("<" + self.struct_fmt, int(round(value * self.scale)))

    def decode(self, raw: bytes) -> float:
        if len(raw) != self.size:
            raise ValueError("expected %d bytes, got %d" % (self.size, len(raw)))
        value = struct.unpack("<" + self.struct_fmt, raw)[0]
        return value / self.scale if self.scale != 1.0 else value

    def label(self, value: float) -> str:
        if self.scale != 1.0:
            return "%g (raw %d)" % (value, int(round(value * self.scale)))
        if self.struct_fmt[-1] in "fd":
            return "%g" % value
        return "%d" % value


ENCODINGS: dict[str, Encoding] = {
    "int8": Encoding("int8", 1, "b"),
    "uint8": Encoding("uint8", 1, "B"),
    "int16": Encoding("int16", 2, "h"),
    "uint16": Encoding("uint16", 2, "H"),
    "int32": Encoding("int32", 4, "i"),
    "uint32": Encoding("uint32", 4, "I"),
    "float32": Encoding("float32", 4, "f"),
    "float64": Encoding("float64", 8, "d"),
    "uint8x10": Encoding("uint8x10", 1, "B", 10.0),
    "uint16x10": Encoding("uint16x10", 2, "H", 10.0),
    "uint16x100": Encoding("uint16x100", 2, "H", 100.0),
    "int32x1000": Encoding("int32x1000", 4, "i", 1000.0),
}

DEFAULT_ENCODINGS = (
    "int8",
    "uint8",
    "int16",
    "uint16",
    "int32",
    "uint32",
    "float32",
    "float64",
    "uint8x10",
    "uint16x10",
    "uint16x100",
    "int32x1000",
)


@dataclass
class Candidate:
    offset: int
    encoding: Encoding
    value: float
    raw: bytes
    score: int = 0
    reasons: list[str] = None

    def __post_init__(self) -> None:
        if self.reasons is None:
            self.reasons = []

    @property
    def key(self) -> tuple[int, str]:
        return self.offset, self.encoding.name

    def context(self, data: bytes, radius: int = 8) -> str:
        start = max(0, self.offset - radius)
        end = min(len(data), self.offset + self.encoding.size + radius)
        before = data[start:self.offset]
        after = data[self.offset + self.encoding.size:end]
        return "%s[%s]%s" % (before.hex(), self.raw.hex(), after.hex())

    def describe(self) -> str:
        return (
            "0x%06X  %-11s %-8s score=%3d  %s"
            % (
                self.offset,
                self.encoding.name,
                self.encoding.label(self.value),
                self.score,
                self.context_text(),
            )
        )

    def context_text(self) -> str:
        return ", ".join(self.reasons) if self.reasons else "-"


@dataclass
class Ladder:
    offset: int
    width: int
    encoding: Encoding
    values: list[float]
    switch_table: bool = False


# --------------------------------------------------------------------- helpers


def get_encoding(name: "str | Encoding") -> Encoding:
    if isinstance(name, Encoding):
        return name
    try:
        return ENCODINGS[name]
    except KeyError:
        raise PatchError(
            "unknown encoding %r (choose from: %s)"
            % (name, ", ".join(sorted(ENCODINGS)))
        )


def read_value(data: bytes, offset: int, encoding: "Encoding | str") -> float:
    enc = get_encoding(encoding) if isinstance(encoding, str) else encoding
    return enc.decode(data[offset:offset + enc.size])


def apply_patch(
    data: bytes,
    offset: int,
    encoding: "Encoding | str",
    new_value: float,
) -> tuple[bytes, float, float]:
    """Write ``new_value`` at ``offset``; return (new_data, old, new)."""
    enc = get_encoding(encoding) if isinstance(encoding, str) else encoding
    if offset < 0 or offset + enc.size > len(data):
        raise PatchError(
            "0x%X (%s) does not fit inside %d-byte buffer"
            % (offset, enc.name, len(data))
        )
    old = enc.decode(data[offset:offset + enc.size])
    try:
        replacement = enc.encode(new_value)
    except (OverflowError, struct.error) as exc:
        raise PatchError(
            "%g cannot be encoded as %s: %s" % (new_value, enc.name, exc)
        )
    patched = bytearray(data)
    patched[offset:offset + enc.size] = replacement
    return bytes(patched), old, new_value


def parse_value_spec(spec: str) -> list[float]:
    """Parse ``"8-21,25"`` into ``[8, 9, ..., 21, 25]``."""
    values: list[float] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            values.extend(float(v) for v in range(int(start), int(end) + 1))
        else:
            values.append(float(part))
    return sorted(set(values))


# ---------------------------------------------------------------------- scoring


def _score_candidate(
    data: bytes,
    offset: int,
    enc: Encoding,
    in_ladder: bool = False,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if offset < sfu.IMAGE_OFFSET:
        score -= 100
        reasons.append("inside record/padding")
    else:
        score += 10
        reasons.append("in firmware image")

    if enc.size > 1:
        if offset % enc.size == 0:
            score += 5
            reasons.append("aligned")
        else:
            score -= 5
            reasons.append("unaligned")

    if offset >= sfu.IMAGE_OFFSET:
        distance = abs(offset - MODEL_TABLE_OFFSET)
        if distance <= 0x400:
            score += 30
            reasons.append("near model-name table")
        elif distance <= 0x2000:
            score += 10
            reasons.append("near model-name region")
        if abs(offset - AES_SBOX_OFFSET) <= 0x40:
            score += 15
            reasons.append("next to AES tables")
        if offset < sfu.IMAGE_OFFSET + 0x100:
            score += 5
            reasons.append("near vector table")

    if in_ladder:
        score += 60
        reasons.append("part of increasing torque ladder")
    return score, reasons


def _find_all(data: bytes, pattern: bytes) -> Iterable[int]:
    if not pattern:
        return
    start = 0
    while True:
        index = data.find(pattern, start)
        if index < 0:
            return
        yield index
        start = index + 1


def _thumb_switch_table_before(data: bytes, offset: int) -> bool:
    """True when ``offset`` directly follows a Thumb-2 TBB/TBH instruction.

    ``E8 DF`` / ``F0 xx`` is ``tbb [rn, rm]`` and the byte (or halfword)
    table follows immediately.  Such tables routinely look like a small
    increasing run of numbers and are a classic false positive for a torque
    ladder heuristic.
    """
    for back in range(4, 17):
        start = offset - back
        if start < 0 or start + 4 > len(data):
            continue
        first, second = struct.unpack_from("<HH", data, start)
        if first == 0xE8DF and (second & 0xFFF0) == 0xF000:
            return True
    return False


def scan(
    data: bytes,
    values: Sequence[float],
    encodings: Optional[Sequence[str]] = None,
    include_ladders: bool = True,
) -> tuple[list[Candidate], list[Ladder]]:
    """Return (candidates, ladders) for the requested torque ``values``."""
    enc_names = tuple(encodings) if encodings else DEFAULT_ENCODINGS
    candidates: list[Candidate] = []
    seen: set[tuple[int, str]] = set()

    ladders = find_ladders(data) if include_ladders else []
    ladder_map = {
        (ladder.offset + index * ladder.width, ladder.encoding.name): ladder
        for ladder in ladders
        for index in range(len(ladder.values))
    }

    for enc_name in enc_names:
        enc = get_encoding(enc_name)
        for value in values:
            try:
                pattern = enc.encode(value)
            except (OverflowError, struct.error):
                continue
            for offset in _find_all(data, pattern):
                key = (offset, enc.name)
                if key in seen:
                    continue
                try:
                    decoded = enc.decode(data[offset:offset + enc.size])
                except (struct.error, ValueError):
                    continue
                if abs(decoded - value) > 1e-6:
                    continue
                seen.add(key)
                in_ladder = key in ladder_map
                score, reasons = _score_candidate(data, offset, enc, in_ladder)
                if in_ladder:
                    ladder = ladder_map[key]
                    if ladder.switch_table:
                        score -= 200
                        reasons.append(
                            "inside Thumb-2 switch table @0x%06X" % ladder.offset
                        )
                    else:
                        reasons.append(
                            "ladder @0x%06X %s"
                            % (
                                ladder.offset,
                                "/".join("%g" % v for v in ladder.values),
                            )
                        )
                candidates.append(
                    Candidate(
                        offset=offset,
                        encoding=enc,
                        value=decoded,
                        raw=data[offset:offset + enc.size],
                        score=score,
                        reasons=reasons,
                    )
                )
    candidates.sort(key=lambda c: (-c.score, c.offset, c.encoding.name))
    return candidates, ladders


def find_ladders(
    data: bytes,
    widths: Sequence[int] = (1, 2, 4),
    min_run: int = 3,
    low: float = 5,
    high: float = 30,
) -> list[Ladder]:
    """Find strictly increasing runs of small integers, a torque-table shape."""
    ladders: list[Ladder] = []
    for width, enc_name in ((1, "uint8"), (2, "uint16"), (4, "uint32")):
        if width not in widths:
            continue
        enc = get_encoding(enc_name)
        offset = 0
        limit = len(data) - width * min_run
        while offset <= limit:
            values: list[float] = []
            cursor = offset
            while cursor + width <= len(data):
                value = enc.decode(data[cursor:cursor + width])
                if value < low or value > high:
                    break
                if values and value <= values[-1]:
                    break
                if values and (value - values[-1]) > 8:
                    break
                values.append(value)
                cursor += width
            if len(values) >= min_run:
                ladders.append(
                    Ladder(
                        offset=offset,
                        width=width,
                        encoding=enc,
                        values=values,
                        switch_table=_thumb_switch_table_before(data, offset),
                    )
                )
                offset = cursor
            else:
                offset += 1
    return ladders


def ladder_candidates(
    ladders: Sequence[Ladder],
    stock: float,
    target: float,
) -> list[Candidate]:
    """Turn ladder entries matching ``stock`` into high-confidence candidates."""
    candidates: list[Candidate] = []
    for ladder in ladders:
        if ladder.switch_table:
            continue
        interests = set(ladder.values)
        if not interests <= set(KNOWN_TORQUES):
            # Jump/offset tables and calibration runs frequently contain
            # small increasing numbers; only values that are all real SKU
            # ratings are meaningful.
            continue
        if not ({stock, target} <= interests):
            # Only a ladder containing both the stock and target rating is
            # strong evidence: that shape is a model table, not code.
            continue
        for index, value in enumerate(ladder.values):
            if value != stock:
                continue
            offset = ladder.offset + index * ladder.width
            candidates.append(
                Candidate(
                    offset=offset,
                    encoding=ladder.encoding,
                    value=value,
                    raw=ladder.encoding.encode(value),
                    score=90,
                    reasons=[
                        "torque ladder @0x%06X (%s)"
                        % (
                            ladder.offset,
                            "/".join("%g" % v for v in ladder.values),
                        )
                    ],
                )
            )
    return candidates


def locate_encoding_at(
    data: bytes,
    offset: int,
    expected: float,
    encodings: Optional[Sequence[str]] = None,
) -> Optional[Encoding]:
    """Find which encoding at ``offset`` decodes to ``expected``."""
    for name in (encodings or DEFAULT_ENCODINGS):
        enc = get_encoding(name)
        if offset + enc.size > len(data):
            continue
        try:
            if abs(enc.decode(data[offset:offset + enc.size]) - expected) < 1e-6:
                return enc
        except (struct.error, ValueError):
            continue
    return None


def unique_candidate(
    data: bytes,
    stock: float,
    target: float,
    min_score: int = 60,
) -> tuple[Optional[Candidate], list[Candidate], list[Ladder]]:
    """Attempt an automatic choice; ambiguity yields ``(None, candidates, ladders)``."""
    candidates, ladders = scan(data, [stock])
    strong = [c for c in candidates if c.score >= min_score]
    strong.extend(ladder_candidates(ladders, stock, target))
    dedup: dict[tuple[int, str], Candidate] = {}
    for candidate in strong:
        dedup.setdefault(candidate.key, candidate)
    strong = sorted(dedup.values(), key=lambda c: (-c.score, c.offset))
    if len(strong) == 1:
        return strong[0], candidates, ladders
    return None, strong, ladders


def patch_byte(
    decrypted: "sfu.DecryptedSFU",
    offset: int,
    encoding: "Encoding | str",
    new_value: float,
) -> "sfu.DecryptedSFU":
    """Apply a patch at a file-relative offset inside an image byte buffer."""
    enc = get_encoding(encoding) if isinstance(encoding, str) else encoding
    if offset < sfu.IMAGE_OFFSET:
        raise PatchError(
            "0x%X is inside the header/record region; only image offsets "
            "(>= 0x%X) are patchable" % (offset, sfu.IMAGE_OFFSET)
        )
    image_offset = offset - sfu.IMAGE_OFFSET
    image = decrypted.image
    patched_image, _, _ = apply_patch(image, image_offset, enc, new_value)
    return decrypted.with_image(patched_image)
