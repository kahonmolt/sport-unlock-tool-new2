#!/usr/bin/env python3
"""Simagic Torque Unlock Tool.

Offline backup / patch / restore for Simagic ``.sfu`` firmware packages.

Examples
--------
Inspect a package::

    python tools/simagic_unlock.py info --sfu stock.sfu

Back up (decrypt) a package::

    python tools/simagic_unlock.py backup --sfu stock.sfu --output backup/

Patch the torque rating (auto candidate selection)::

    python tools/simagic_unlock.py patch --sfu stock.sfu \\
        --output patched.sfu --torque 12

If no unique candidate exists (the normal case for the Alpha Evo image,
see FINDINGS_READONLY.md), the tool refuses to guess and asks for an
explicit ``--offset`` plus optional ``--encoding``.

Restore from the sidecar written by ``patch``::

    python tools/simagic_unlock.py restore --sfu patched.sfu \\
        --output stock_again.sfu

Exit codes: 0 ok, 2 invalid input, 3 no candidate, 4 ambiguous candidate,
5 signature failure, 6 HID failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import encrypt_sfu  # noqa: E402
import patch_nvm  # noqa: E402
from utils import hid, sfu  # noqa: E402

EXIT_OK = 0
EXIT_INPUT = 2
EXIT_NO_CANDIDATE = 3
EXIT_AMBIGUOUS = 4
EXIT_SIGNATURE = 5
EXIT_DEVICE = 6


class CLIError(Exception):
    def __init__(self, message: str, code: int = EXIT_INPUT) -> None:
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------- helpers


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_offset(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        raise CLIError("invalid offset %r (use decimal or 0x-hex)" % (value,))


def _load(path: str) -> tuple[sfu.SFU, "sfu.DecryptedSFU", bytes]:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise CLIError("cannot read %s: %s" % (path, exc))
    try:
        package = sfu.SFU.from_bytes(raw)
    except sfu.SFUError as exc:
        raise CLIError("%s: %s" % (path, exc))
    return package, package.decrypt(), raw


def _write_guard(output: str, source: str, force: bool) -> None:
    out = Path(output).resolve()
    src = Path(source).resolve()
    if out == src and not force:
        raise CLIError(
            "refusing to overwrite the input in place; choose another --output "
            "or pass --force"
        )


def _signature_note(spec: Optional[encrypt_sfu.SignatureSpec]) -> str:
    return spec.label if spec else "unknown (stored digest could not be reproduced)"


def _candidate_json(candidate: patch_nvm.Candidate, data: bytes) -> dict[str, Any]:
    return {
        "offset": candidate.offset,
        "offset_hex": "0x%X" % candidate.offset,
        "encoding": candidate.encoding.name,
        "value": candidate.value,
        "raw": candidate.raw.hex(),
        "score": candidate.score,
        "reasons": candidate.reasons,
        "context": candidate.context(data),
    }


def _choose_candidate(
    dec: "sfu.DecryptedSFU",
    args: argparse.Namespace,
    stock: float,
    target: float,
) -> patch_nvm.Candidate:
    data = dec.full_bytes
    offset = _parse_offset(args.offset)
    if offset is not None:
        encoding = args.encoding
        if encoding is None:
            found = patch_nvm.locate_encoding_at(data, offset, stock)
            if found is None:
                if not args.force:
                    raise CLIError(
                        "no supported encoding at 0x%X decodes to %g; pass "
                        "--encoding and --force to override" % (offset, stock)
                    )
                encoding = "int8"
                print(
                    "warning: no encoding at 0x%X decodes to %g; forcing int8"
                    % (offset, stock),
                    file=sys.stderr,
                )
            else:
                encoding = found.name
        enc = patch_nvm.get_encoding(encoding)
        value = patch_nvm.read_value(data, offset, enc)
        if abs(value - stock) > 1e-6 and not args.force:
            raise CLIError(
                "0x%X (%s) currently holds %g, not the expected stock value %g; "
                "pass the right --stock-torque or --force"
                % (offset, enc.name, value, stock)
            )
        return patch_nvm.Candidate(
            offset=offset,
            encoding=enc,
            value=value,
            raw=data[offset:offset + enc.size],
            score=100,
            reasons=["explicit offset"],
        )

    candidate, strong, ladders = patch_nvm.unique_candidate(data, stock, target)
    if candidate is not None:
        return candidate

    if strong:
        lines = [
            "  " + _candidate_json(item, data)["offset_hex"]
            + "  " + item.encoding.name
            + "  " + item.encoding.label(item.value)
            + "  score=" + str(item.score)
            for item in strong[:10]
        ]
        raise CLIError(
            "ambiguous max_torque candidate (%d strong matches); choose one "
            "with --offset/--encoding:\n%s" % (len(strong), "\n".join(lines)),
            EXIT_AMBIGUOUS,
        )

    ladder_text = ""
    informative = [ladder for ladder in ladders if not ladder.switch_table]
    if informative:
        ladder_text = "\n  torque-shaped ladders found: " + ", ".join(
            "0x%X (%s)" % (
                ladder.offset,
                "/".join("%g" % v for v in ladder.values),
            )
            for ladder in informative[:5]
        )
    raise CLIError(
        "no unique max_torque candidate for %g Nm in this image.%s\n"
        "The Alpha Evo image is model-agnostic and carries no rating constant "
        "(see FINDINGS_READONLY.md section 1); max_torque is a per-unit NVM "
        "value. Use 'scan' to inspect candidates, or patch an explicit offset "
        "with --offset/--encoding."
        % (stock, ladder_text),
        EXIT_NO_CANDIDATE,
    )


# ------------------------------------------------------------------- commands


def cmd_backup(args: argparse.Namespace) -> int:
    package, dec, raw = _load(args.sfu)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(args.sfu).stem

    decrypted_path = out / (stem + "_decrypted.bin")
    image_path = out / (stem + "_image.bin")
    header_path = out / (stem + "_header.json")
    meta_path = out / (stem + "_backup.json")

    dec.write_decrypted(decrypted_path)
    dec.write_image(image_path)
    sfu.dump_json(header_path, dec.header.as_dict())

    signature_spec = encrypt_sfu.detect(raw, dec)
    meta = {
        "tool": "simagic_unlock",
        "created": sfu.now_iso(),
        "source": str(Path(args.sfu).resolve()),
        "source_size": len(raw),
        "source_sha256": _sha256(raw),
        "decrypted_sha256": _sha256(dec.full_bytes),
        "signature": encrypt_sfu.describe(raw, dec),
        **dec.describe(),
    }
    sfu.dump_json(meta_path, meta)

    print("Backed up %s" % args.sfu)
    print("  decrypted : %s" % decrypted_path)
    print("  image     : %s (%d bytes)" % (image_path, len(dec.image)))
    print("  header    : %s" % header_path)
    print("  metadata  : %s" % meta_path)
    print("  image sha256: %s" % dec.image_sha256())
    print("  signature : %s" % _signature_note(signature_spec))

    if args.hid:
        try:
            summary = hid.backup(out / "hid")
            print(
                "  HID       : status max_torque=%s, %d pages -> %s"
                % (
                    summary.get("status", {}).get("max_torque"),
                    len(summary.get("pages", {})),
                    out / "hid",
                )
            )
        except hid.HIDUnavailable as exc:
            print("  HID       : skipped (%s)" % exc, file=sys.stderr)
        except Exception as exc:  # pragma: no cover - hardware dependent
            print("  HID       : failed (%s)" % exc, file=sys.stderr)
    return EXIT_OK


def cmd_patch(args: argparse.Namespace) -> int:
    package, dec, raw = _load(args.sfu)
    _write_guard(args.output, args.sfu, args.force)

    target = float(args.torque)
    stock = float(args.stock_torque)
    if not 1 <= target <= 60:
        raise CLIError("--torque %g is outside the plausible range 1..60" % target)

    detected = encrypt_sfu.detect(raw, dec)
    candidate = _choose_candidate(dec, args, stock, target)

    patched = patch_nvm.patch_byte(dec, candidate.offset, candidate.encoding, target)
    written_digest = dec.digest
    used_spec: Optional[encrypt_sfu.SignatureSpec] = None

    if args.signature == "auto":
        if detected is not None:
            try:
                out_bytes, written_digest = encrypt_sfu.resign(patched, detected)
                used_spec = detected
            except encrypt_sfu.SignatureError as exc:
                raise CLIError(str(exc), EXIT_SIGNATURE)
        elif args.dry_run:
            print(
                "warning: stored digest could not be reproduced; a real run "
                "will refuse unless --signature keep/sha1/sha256 is given",
                file=sys.stderr,
            )
            out_bytes = patched.to_sfu_bytes()
        else:
            raise CLIError(
                "stored digest at 0x4C could not be reproduced by SHA-1 or "
                "SHA-256 over the supported coverages (see FINDINGS.md 6.5). "
                "Refusing to emit a package with an invalid signature.\n"
                "Re-run with --signature keep to preserve the original (stale) "
                "digest, or --signature sha1/sha256 to force a recomputed digest.",
                EXIT_SIGNATURE,
            )
    elif args.signature == "keep":
        out_bytes = encrypt_sfu.keep_digest(patched)
    else:
        used_spec = encrypt_sfu.SignatureSpec(args.signature, "encrypted_payload")
        out_bytes, written_digest = encrypt_sfu.resign(patched, used_spec)
        if detected != used_spec:
            print(
                "warning: forced %s, but the stock digest is %s; the wheel's "
                "bootloader may reject this package"
                % (used_spec.label, _signature_note(detected)),
                file=sys.stderr,
            )

    image_offset = candidate.offset - sfu.IMAGE_OFFSET
    summary = {
        "source": str(Path(args.sfu).resolve()),
        "output": str(Path(args.output).resolve()),
        "source_sha256": _sha256(raw),
        "output_sha256": _sha256(out_bytes),
        "patch": {
            "offset": candidate.offset,
            "offset_hex": "0x%X" % candidate.offset,
            "image_offset": image_offset,
            "image_offset_hex": "0x%X" % image_offset,
            "encoding": candidate.encoding.name,
            "old_value": candidate.value,
            "new_value": target,
            "old_raw": candidate.raw.hex(),
            "new_raw": patch_nvm.get_encoding(candidate.encoding).encode(target).hex(),
            "reasons": candidate.reasons,
        },
        "signature": {
            "mode": args.signature,
            "spec": used_spec.as_dict() if used_spec else None,
            "validated_against_stock": detected is not None
            and detected == used_spec,
            "written_digest": written_digest.hex(),
            "original_digest": dec.digest.hex(),
        },
        "created": sfu.now_iso(),
    }

    print("Patch plan for %s" % args.sfu)
    print(
        "  offset 0x%X (%s): %s -> %s"
        % (
            candidate.offset,
            candidate.encoding.name,
            candidate.encoding.label(candidate.value),
            candidate.encoding.label(target),
        )
    )
    print("  context: %s" % candidate.context(dec.full_bytes))
    print("  signature: %s" % _signature_note(used_spec))
    if args.signature == "keep":
        print("  warning: original digest preserved; patched payload is unsigned")

    if args.dry_run:
        print("dry run: nothing written")
        return EXIT_OK

    Path(args.output).write_bytes(out_bytes)
    sidecar = Path(str(args.output) + ".patch.json")
    sfu.dump_json(sidecar, summary)
    print("Wrote %s (%d bytes)" % (args.output, len(out_bytes)))
    print("Sidecar %s (used by restore)" % sidecar)
    return EXIT_OK


def _find_sidecar(path: str) -> Optional[Path]:
    candidate = Path(str(path) + ".patch.json")
    if candidate.exists():
        return candidate
    return None


def cmd_restore(args: argparse.Namespace) -> int:
    package, dec, raw = _load(args.sfu)
    _write_guard(args.output, args.sfu, args.force)
    sidecar_path = Path(args.sidecar) if args.sidecar else _find_sidecar(args.sfu)

    restored_digest: Optional[bytes] = None
    used_spec: Optional[encrypt_sfu.SignatureSpec] = None

    if sidecar_path is not None:
        try:
            meta = json.loads(sidecar_path.read_text(encoding="utf-8"))
            info = meta["patch"]
            offset = int(info["offset"])
            encoding = str(info["encoding"])
            old_value = float(info["old_value"])
            new_value = float(info["new_value"])
            original_digest = meta.get("signature", {}).get("original_digest")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise CLIError("invalid sidecar %s: %s" % (sidecar_path, exc))

        current = patch_nvm.read_value(dec.full_bytes, offset, encoding)
        if abs(current - new_value) > 1e-6 and not args.force:
            raise CLIError(
                "sidecar expects %g at 0x%X but the file holds %g; pass --force "
                "to restore anyway" % (new_value, offset, current)
            )
        restored = patch_nvm.patch_byte(dec, offset, encoding, old_value)
        if original_digest:
            try:
                restored_digest = bytes.fromhex(original_digest)
                restored = restored.with_digest(restored_digest)
            except ValueError as exc:
                raise CLIError("sidecar has an invalid original digest: %s" % exc)
        out_bytes = restored.to_sfu_bytes()
        expected_sha = meta.get("source_sha256")
        exact = expected_sha is not None and _sha256(out_bytes) == expected_sha
        print("Restoring from sidecar %s" % sidecar_path)
        print(
            "  offset 0x%X (%s): %s -> %s"
            % (
                offset,
                encoding,
                patch_nvm.get_encoding(encoding).label(new_value),
                patch_nvm.get_encoding(encoding).label(old_value),
            )
        )
        print("  byte-identical to original: %s" % ("yes" if exact else "no"))
    else:
        stock = float(args.to_torque)
        current = float(args.from_torque)
        candidate = _choose_candidate(dec, args, current, stock)
        restored = patch_nvm.patch_byte(dec, candidate.offset, candidate.encoding, stock)
        detected = encrypt_sfu.detect(raw, dec)
        if detected is not None:
            out_bytes, restored_digest = encrypt_sfu.resign(restored, detected)
            used_spec = detected
        else:
            out_bytes = encrypt_sfu.keep_digest(restored)
            restored_digest = dec.digest
            print(
                "warning: no validated digest specification; keeping the "
                "existing digest",
                file=sys.stderr,
            )
        print("Restoring without a sidecar")
        print(
            "  offset 0x%X (%s): %s -> %s"
            % (
                candidate.offset,
                candidate.encoding.name,
                candidate.encoding.label(current),
                candidate.encoding.label(stock),
            )
        )
        print("  signature: %s" % _signature_note(used_spec))

    if args.dry_run:
        print("dry run: nothing written")
        return EXIT_OK

    Path(args.output).write_bytes(out_bytes)
    print("Wrote %s (%d bytes)" % (args.output, len(out_bytes)))
    if sidecar_path is not None and not args.keep_sidecar:
        removed = Path(str(args.output) + ".patch.json")
        if removed.exists():
            removed.unlink()
    return EXIT_OK


def cmd_info(args: argparse.Namespace) -> int:
    package, dec, raw = _load(args.sfu)
    info = {
        "source": str(Path(args.sfu).resolve()),
        "size": len(raw),
        "sha256": _sha256(raw),
        **dec.describe(),
        "signature": encrypt_sfu.describe(raw, dec),
    }
    if info["signature"]["validated"]:
        spec = info["signature"]["spec"]
        info["signature"]["spec"] = spec
    if args.json:
        print(json.dumps(info, indent=2, sort_keys=True))
        return EXIT_OK

    header = info["header"]
    print("File      : %s (%d bytes)" % (info["source"], info["size"]))
    print("SHA-256   : %s" % info["sha256"])
    print(
        "Device    : %s  version %s  PID 0x%04X  VID 0x%04X"
        % (
            header["device"],
            header["version"],
            int(header["pid"], 16),
            int(header["vid"], 16),
        )
    )
    print(
        "UUIDs     : product %s  board %s"
        % (header["product_uuid"], header["board_uuid"])
    )
    record = info["record"]
    print(
        "Record    : marker %s  image_len %d  digest %s  ok=%s"
        % (
            record["marker"],
            record["image_length"],
            record["digest"],
            record["record_ok"],
        )
    )
    image = info["image"]
    print("Image     : %d bytes  sha256 %s" % (image["size"], image["sha256"]))
    if image["vector_table"]:
        vt = image["vector_table"]
        print(
            "Vector    : offset %s  SP %s  reset %s"
            % (vt["offset"], vt["initial_sp"], vt["reset_handler"])
        )
    else:
        print("Vector    : none found")
    sig = info["signature"]
    print("Signature : %s" % sig["label"])
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    package, dec, raw = _load(args.sfu)
    data = dec.full_bytes
    values = patch_nvm.parse_value_spec(args.values)
    encodings = args.encodings or None
    candidates, ladders = patch_nvm.scan(data, values, encodings=encodings)

    print("Scanning %s for torque values %s" % (args.sfu, ",".join("%g" % v for v in values)))
    print("Torque-shaped ladders: %d" % len(ladders))
    for ladder in ladders[:10]:
        print(
            "  0x%06X  width=%d  %s%s"
            % (
                ladder.offset,
                ladder.width,
                "/".join("%g" % v for v in ladder.values),
                "  [Thumb switch table - ignored]" if ladder.switch_table else "",
            )
        )
    print("Candidates (top %d of %d):" % (min(args.limit, len(candidates)), len(candidates)))
    for candidate in candidates[: args.limit]:
        print(
            "  0x%06X  %-11s %-10s score=%3d  %s"
            % (
                candidate.offset,
                candidate.encoding.name,
                candidate.encoding.label(candidate.value),
                candidate.score,
                candidate.context(data),
            )
        )
    if not candidates:
        print("  none")
    return EXIT_OK

def cmd_verify(args: argparse.Namespace) -> int:
    package, dec, raw = _load(args.sfu)
    roundtrip = dec.to_sfu_bytes()
    ok = roundtrip == raw
    sig = encrypt_sfu.describe(raw, dec)
    vt = sfu.find_vector_table(dec.image)
    print("Verify %s" % args.sfu)
    print("  decrypt/encrypt round-trip: %s" % ("PASS" if ok else "FAIL"))
    print("  record structure          : %s" % ("PASS" if dec.record_ok() else "FAIL"))
    print("  vector table              : %s" % ("PASS" if vt else "FAIL"))
    print("  signature                 : %s" % sig["label"])
    if not ok:
        raise CLIError("round-trip mismatch: re-encryption is not byte-identical")
    if not dec.record_ok():
        raise CLIError("record structure is not the expected marker/length/padding")
    if not vt:
        raise CLIError("no Cortex-M vector table found in the decrypted image")
    return EXIT_OK


# ----------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="simagic_unlock.py",
        description="Offline Simagic .sfu backup / patch / restore tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    backup = sub.add_parser("backup", help="decrypt and archive an SFU package")
    backup.add_argument("--sfu", required=True, help="input .sfu file")
    backup.add_argument("--output", required=True, help="output directory")
    backup.add_argument("--hid", action="store_true", help="also dump device status/pages via HID")
    backup.set_defaults(func=cmd_backup)

    patch = sub.add_parser("patch", help="patch max_torque and re-encrypt")
    patch.add_argument("--sfu", required=True, help="input stock .sfu file")
    patch.add_argument("--output", required=True, help="output .sfu file")
    patch.add_argument("--torque", type=float, default=12.0, help="target rating in Nm (default 12)")
    patch.add_argument("--stock-torque", type=float, default=9.0, help="expected current rating (default 9)")
    patch.add_argument("--offset", help="explicit decrypted-file offset (decimal or 0x-hex)")
    patch.add_argument("--encoding", help="force an encoding (int8, uint16, float32, ...)")
    patch.add_argument(
        "--signature",
        choices=("auto", "keep", "sha1", "sha256"),
        default="auto",
        help="digest handling: validate+re-sign, keep original, or force an algorithm",
    )
    patch.add_argument("--dry-run", action="store_true", help="print the plan without writing")
    patch.add_argument("--force", action="store_true", help="allow explicit offsets/overwrites")
    patch.set_defaults(func=cmd_patch)

    restore = sub.add_parser("restore", help="reverse a patch, preferably from the sidecar")
    restore.add_argument("--sfu", required=True, help="input patched .sfu file")
    restore.add_argument("--output", required=True, help="output .sfu file")
    restore.add_argument("--from-torque", type=float, default=12.0, help="current rating without a sidecar")
    restore.add_argument("--to-torque", type=float, default=9.0, help="rating to restore without a sidecar")
    restore.add_argument("--offset", help="explicit decrypted-file offset")
    restore.add_argument("--encoding", help="force an encoding")
    restore.add_argument("--sidecar", help="path to the patch sidecar JSON")
    restore.add_argument("--keep-sidecar", action="store_true", help="do not remove the output sidecar")
    restore.add_argument("--dry-run", action="store_true", help="print the plan without writing")
    restore.add_argument("--force", action="store_true", help="allow mismatched values/overwrites")
    restore.set_defaults(func=cmd_restore)

    info = sub.add_parser("info", help="print header, record, image and signature info")
    info.add_argument("--sfu", required=True, help="input .sfu file")
    info.add_argument("--json", action="store_true", help="machine-readable output")
    info.set_defaults(func=cmd_info)

    scan = sub.add_parser("scan", help="list torque-value candidates in the image")
    scan.add_argument("--sfu", required=True, help="input .sfu file")
    scan.add_argument("--values", default="8-21", help="values to search (default 8-21)")
    scan.add_argument("--encodings", nargs="*", help="subset of encodings to try")
    scan.add_argument("--limit", type=int, default=25, help="maximum candidates to print")
    scan.set_defaults(func=cmd_scan)

    verify = sub.add_parser("verify", help="check round-trip, record and vector table")
    verify.add_argument("--sfu", required=True, help="input .sfu file")
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CLIError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return exc.code
    except encrypt_sfu.SignatureError as exc:
        print("signature error: %s" % exc, file=sys.stderr)
        return EXIT_SIGNATURE
    except patch_nvm.PatchError as exc:
        print("patch error: %s" % exc, file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":
    sys.exit(main())
