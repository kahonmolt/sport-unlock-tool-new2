"""Tests for the Simagic Torque Unlock Tool.

Run from the repository root::

    python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import encrypt_sfu  # noqa: E402
import patch_nvm  # noqa: E402
import simagic_unlock  # noqa: E402
from utils import crypto, sfu  # noqa: E402

FIXTURE = TOOLS / "Alpha_Evo_Sport_decrypted.bin"
STOCK_SFU_SHA256 = (
    "b20d4606777720db7fb37cdf2c57efee"
    "17d84d97a67b11c92e90821098e52a47"
)
STOCK_IMAGE_SHA256 = (
    "b848b8afa10047e7d1c295dacb4e8d9a"
    "440f4f5df86db09361ea96f4b4530191"
)
STOCK_DIGEST = "77ddb093e92941e22a91777adbb3012846e30259"
# Thumb-2 TBB jump table at 0x1E68C: 03 06 09 0c 0f 00 18
SWITCH_TABLE_LADDER = 0x1E68D
SAFE_PATCH_OFFSET = 0x27EBC  # an int8 9 in code, used only as a test target


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _quiet(func, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = func(*args, **kwargs)
    return code, out.getvalue(), err.getvalue()


@unittest.skipUnless(FIXTURE.exists(), "decrypted fixture is not present")
class CryptoAndContainerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = FIXTURE.read_bytes()
        cls.dec = sfu.DecryptedSFU.from_decrypted_bytes(cls.raw)
        cls.stock_sfu = cls.dec.to_sfu_bytes()

    def test_roundtrip_reproduces_stock_sfu(self) -> None:
        self.assertEqual(_sha256(self.stock_sfu), STOCK_SFU_SHA256)

    def test_crypt_is_symmetric(self) -> None:
        data = bytes(range(64))
        self.assertEqual(crypto.crypt(crypto.crypt(data)), data)

    def test_header_fields(self) -> None:
        header = self.dec.header
        self.assertEqual(header.magic, "SIMPROSFU100")
        self.assertEqual(header.device, "alpha_evo1")
        self.assertEqual(header.version, "2.2.3")
        self.assertEqual(header.header_len, 0x40)
        self.assertEqual(header.product_uuid, 0x01080000)
        self.assertEqual(header.board_uuid, 0x01080000)
        self.assertEqual(header.pid, 0x0500)
        self.assertEqual(header.vid, 0x3670)
        self.assertEqual(header.blob_len, len(self.raw) - 0x40)

    def test_record_structure(self) -> None:
        self.assertTrue(self.dec.record_ok())
        self.assertEqual(self.dec.marker, b"\xFF" * 8)
        self.assertEqual(self.dec.image_length, len(self.dec.image))
        self.assertEqual(self.dec.digest.hex(), STOCK_DIGEST)

    def test_image_and_vector_table(self) -> None:
        self.assertEqual(_sha256(self.dec.image), STOCK_IMAGE_SHA256)
        vector = sfu.find_vector_table(self.dec.image)
        self.assertIsNotNone(vector)
        self.assertEqual(vector["initial_sp"], "0x20015BE0")
        self.assertEqual(vector["reset_handler"], "0x080103B5")

    def test_wrong_magic_rejected(self) -> None:
        with self.assertRaises(sfu.SFUError):
            sfu.SFU.from_bytes(b"NOTANAUFILE" + b"\x00" * 64)

    def test_digest_validation_reports_unknown_for_stock(self) -> None:
        self.assertIsNone(encrypt_sfu.detect(self.stock_sfu, self.dec))

    def test_digest_detects_sha1_of_encrypted_payload(self) -> None:
        digest = hashlib.sha1(self.stock_sfu[0x100:]).digest()
        candidate = self.dec.with_digest(digest)
        raw = candidate.to_sfu_bytes()
        spec = encrypt_sfu.detect(raw, candidate)
        self.assertIsNotNone(spec)
        self.assertEqual(spec.label, "sha1(encrypted_payload)")

    def test_digest_detects_sha256_of_encrypted_payload(self) -> None:
        digest = hashlib.sha256(self.stock_sfu[0x100:]).digest()[:20]
        candidate = self.dec.with_digest(digest)
        raw = candidate.to_sfu_bytes()
        spec = encrypt_sfu.detect(raw, candidate)
        self.assertIsNotNone(spec)
        self.assertEqual(spec.label, "sha256(encrypted_payload)")

    def test_resign_after_patch_validates(self) -> None:
        digest = hashlib.sha1(self.stock_sfu[0x100:]).digest()
        seeded = self.dec.with_digest(digest)
        spec = encrypt_sfu.detect(seeded.to_sfu_bytes(), seeded)
        patched = patch_nvm.patch_byte(seeded, SAFE_PATCH_OFFSET, "int8", 12)
        out, written = encrypt_sfu.resign(patched, spec)
        reparsed = sfu.SFU.from_bytes(out).decrypt()
        self.assertEqual(reparsed.digest, written)
        self.assertEqual(encrypt_sfu.detect(out, reparsed), spec)
        self.assertEqual(patch_nvm.read_value(reparsed.full_bytes, SAFE_PATCH_OFFSET, "int8"), 12)

    def test_thumb_switch_table_is_not_a_torque_ladder(self) -> None:
        ladders = patch_nvm.find_ladders(self.raw)
        match = [ladder for ladder in ladders if ladder.offset == SWITCH_TABLE_LADDER]
        self.assertTrue(match, "expected the TBB jump table at 0x1E68D")
        self.assertTrue(match[0].switch_table)
        self.assertEqual(patch_nvm.ladder_candidates(ladders, 9, 12), [])

    def test_auto_patch_refuses_to_guess(self) -> None:
        candidate, strong, _ = patch_nvm.unique_candidate(self.raw, 9, 12)
        self.assertIsNone(candidate)
        self.assertEqual(strong, [])

    def test_explicit_patch_and_reverse(self) -> None:
        patched = patch_nvm.patch_byte(self.dec, SAFE_PATCH_OFFSET, "int8", 12)
        self.assertEqual(
            patch_nvm.read_value(patched.full_bytes, SAFE_PATCH_OFFSET, "int8"), 12
        )
        restored = patch_nvm.patch_byte(patched, SAFE_PATCH_OFFSET, "int8", 9)
        self.assertEqual(_sha256(restored.to_sfu_bytes()), _sha256(self.stock_sfu))

    def test_scaled_encoding(self) -> None:
        enc = patch_nvm.get_encoding("uint16x10")
        raw = enc.encode(9)
        self.assertEqual(raw, b"\x5a\x00")
        self.assertEqual(enc.decode(raw), 9)

    def test_parse_value_spec(self) -> None:
        self.assertEqual(
            patch_nvm.parse_value_spec("9,11-13"),
            [9.0, 11.0, 12.0, 13.0],
        )

    def test_hid_status_report_parses_torque(self) -> None:
        from utils import hid

        raw = bytes.fromhex(
            "230200212b0900000000060000e001010004000000000000000000000000000000"
        )
        parsed = hid.parse_status(raw)
        self.assertEqual(parsed["report_id"], "0x23")
        self.assertEqual(parsed["max_torque"], 9)
        self.assertEqual(hid._json_safe(b"\x01\x02"), "0102")


@unittest.skipUnless(FIXTURE.exists(), "decrypted fixture is not present")
class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dec = sfu.DecryptedSFU.from_decrypted_bytes(FIXTURE.read_bytes())
        cls.stock_bytes = cls.dec.to_sfu_bytes()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.stock = self.dir / "stock.sfu"
        self.stock.write_bytes(self.stock_bytes)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_info_and_verify(self) -> None:
        code, out, _ = _quiet(simagic_unlock.main, ["info", "--sfu", str(self.stock)])
        self.assertEqual(code, 0)
        self.assertIn("alpha_evo1", out)
        self.assertIn("unknown (not reproducible)", out)

        code, out, _ = _quiet(simagic_unlock.main, ["verify", "--sfu", str(self.stock)])
        self.assertEqual(code, 0)
        self.assertIn("round-trip: PASS", out)

    def test_backup_writes_artifacts(self) -> None:
        outdir = self.dir / "backup"
        code, _, _ = _quiet(
            simagic_unlock.main,
            ["backup", "--sfu", str(self.stock), "--output", str(outdir)],
        )
        self.assertEqual(code, 0)
        self.assertTrue((outdir / "stock_decrypted.bin").exists())
        self.assertTrue((outdir / "stock_image.bin").exists())
        meta = json.loads((outdir / "stock_backup.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["source_sha256"], _sha256(self.stock_bytes))
        self.assertEqual(meta["record"]["digest"], STOCK_DIGEST)
        self.assertFalse(meta["signature"]["validated"])

    def test_scan_lists_switch_table(self) -> None:
        code, out, _ = _quiet(
            simagic_unlock.main,
            ["scan", "--sfu", str(self.stock), "--values", "9", "--limit", "3"],
        )
        self.assertEqual(code, 0)
        self.assertIn("Thumb switch table", out)

    def test_auto_patch_refuses(self) -> None:
        out = self.dir / "patched.sfu"
        code, _, err = _quiet(
            simagic_unlock.main,
            ["patch", "--sfu", str(self.stock), "--output", str(out)],
        )
        self.assertEqual(code, simagic_unlock.EXIT_NO_CANDIDATE)
        self.assertIn("model-agnostic", err)
        self.assertFalse(out.exists())

    def test_patch_keep_restore_is_byte_identical(self) -> None:
        patched = self.dir / "patched.sfu"
        code, _, _ = _quiet(
            simagic_unlock.main,
            [
                "patch", "--sfu", str(self.stock), "--output", str(patched),
                "--offset", hex(SAFE_PATCH_OFFSET), "--torque", "12",
                "--signature", "keep",
            ],
        )
        self.assertEqual(code, 0)
        self.assertNotEqual(patched.read_bytes(), self.stock_bytes)
        sidecar = Path(str(patched) + ".patch.json")
        self.assertTrue(sidecar.exists())

        restored = self.dir / "restored.sfu"
        code, out, _ = _quiet(
            simagic_unlock.main,
            ["restore", "--sfu", str(patched), "--output", str(restored)],
        )
        self.assertEqual(code, 0)
        self.assertIn("byte-identical to original: yes", out)
        self.assertEqual(restored.read_bytes(), self.stock_bytes)

    def test_patch_auto_refuses_without_valid_signature(self) -> None:
        patched = self.dir / "patched.sfu"
        code, _, err = _quiet(
            simagic_unlock.main,
            [
                "patch", "--sfu", str(self.stock), "--output", str(patched),
                "--offset", hex(SAFE_PATCH_OFFSET),
            ],
        )
        self.assertEqual(code, simagic_unlock.EXIT_SIGNATURE)
        self.assertIn("could not be reproduced", err)
        self.assertFalse(patched.exists())

    def test_patch_with_validated_signature(self) -> None:
        digest = hashlib.sha1(self.stock_bytes[0x100:]).digest()
        seeded = self.dec.with_digest(digest)
        stock = self.dir / "seeded.sfu"
        stock.write_bytes(seeded.to_sfu_bytes())
        patched = self.dir / "seeded_patched.sfu"
        code, out, _ = _quiet(
            simagic_unlock.main,
            [
                "patch", "--sfu", str(stock), "--output", str(patched),
                "--offset", hex(SAFE_PATCH_OFFSET),
            ],
        )
        self.assertEqual(code, 0)
        self.assertIn("sha1(encrypted_payload)", out)
        reparsed = sfu.SFU.from_file(patched).decrypt()
        spec = encrypt_sfu.detect(patched.read_bytes(), reparsed)
        self.assertEqual(spec.label, "sha1(encrypted_payload)")

    def test_refuses_in_place_overwrite(self) -> None:
        code, _, err = _quiet(
            simagic_unlock.main,
            [
                "patch", "--sfu", str(self.stock), "--output", str(self.stock),
                "--offset", hex(SAFE_PATCH_OFFSET), "--signature", "keep",
            ],
        )
        self.assertEqual(code, simagic_unlock.EXIT_INPUT)
        self.assertIn("refusing to overwrite", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
