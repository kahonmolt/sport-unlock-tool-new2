# Simagic Torque Unlock Tool

Offline backup / patch / restore for Simagic `.sfu` firmware packages.

```
tools/
  simagic_unlock.py        CLI entry point
  encrypt_sfu.py           digest validation + re-signing
  patch_nvm.py             torque candidate search + patching
  utils/crypto.py          AES-256-CTR, key/IV, hash helpers
  utils/sfu.py             .sfu parser/assembler
  utils/hid.py             optional read-only HID backup
  tests/test_simagic_unlock.py
```

## Requirements

- Python 3.10+
- `cryptography` (already used by `decrypt_sfu.py`)
- optional: `hidapi` for `backup --hid`

## Quick start

Inspect a package:

```powershell
python tools\simagic_unlock.py info --sfu stock.sfu
python tools\simagic_unlock.py verify --sfu stock.sfu
```

Back up (decrypt) a package:

```powershell
python tools\simagic_unlock.py backup --sfu stock.sfu --output backup\
# optional read-only device capture:
python tools\simagic_unlock.py backup --sfu stock.sfu --output backup\ --hid
```

Patch a specific byte (auto selection refuses when ambiguous):

```powershell
python tools\simagic_unlock.py patch --sfu stock.sfu --output patched.sfu `
    --offset 0x27EBC --encoding int8 --torque 12 --signature keep
```

Restore using the sidecar written next to the patched file:

```powershell
python tools\simagic_unlock.py restore --sfu patched.sfu --output stock_again.sfu
```

List candidate locations:

```powershell
python tools\simagic_unlock.py scan --sfu stock.sfu --values 8-21 --limit 25
```

Run the tests:

```powershell
python -m unittest discover -s tools/tests -v
```

## Format facts used

```
0x000  64      header (magic, device, version, UUIDs, PID/VID)
0x040  var     AES-256-CTR ciphertext (key/IV from simpro.exe)
               -- decrypted --
0x040  8       FF FF FF FF FF FF FF FF
0x048  u32     image length (= file size - 0x240)
0x04C  byte20  digest (construction unknown)
0x060  0x1E0   FF padding
0x240  var     Cortex-M image
```

CTR is symmetric and position based, so re-encrypting the decrypted body
reproduces the original file byte-for-byte.  The test suite asserts this
against the stock SHA-256 `b20d4606...e52a47`.

## Safety model

The tool refuses to guess in two places:

1. **Torque candidate.** The Alpha Evo image is model-agnostic and contains
   no rating constant (`FINDINGS_READONLY.md` section 1); `max_torque` is a
   per-unit NVM value. Auto-patch therefore exits with code 3 and asks for an
   explicit `--offset`/`--encoding`. Increasing runs of small numbers in
   Thumb-2 code (for example TBB jump tables) are detected and rejected.
2. **Signature.** The 20-byte digest at `0x4C` is not reproducible with
   SHA-1, SHA-256, MD5, SHA-512, HMAC or AES-CMAC over the ranges tested so
   far (`FINDINGS.md` section 6.5). The tool validates a candidate spec
   against the stock file before re-signing. SHA-1 of the encrypted payload
   from `0x100` is tried first, then SHA-256, then the safe plaintext
   coverages. If nothing validates, `--signature auto` exits with code 5.
   `--signature keep` preserves the original (stale) digest and prints a
   warning; a bootloader that verifies the digest may reject such a package.

`restore` replays the patch sidecar (offset, encoding, original digest), so a
patched file made with `--signature keep` can be restored byte-identically to
the stock `.sfu`.

## HID backup

`utils/hid.py` talks to VID `0x3670` / PID `0x0500`, reads the feature
report `0x23` (32 bytes, `max_torque` at byte 5) and the paged `0x90` config
blocks after selecting pages with `80 05 pp pp`.  It never writes a torque
value.  Without `hidapi` or a connected base, `--hid` is skipped with a
warning.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | invalid input / refusing to overwrite |
| 3 | no unique torque candidate |
| 4 | ambiguous torque candidate |
| 5 | signature could not be validated |
| 6 | HID failure |

## Known limitations

- The cloud `PrivilegeActivate` token (`80 1e ... 53 ...`) is not forgeable;
  this tool does not attempt a HID unlock.
- The `0x4C` digest construction remains unknown. Until it is solved, a
  patched `.sfu` is only guaranteed flashable if the bootloader does not
  verify that field.
- The Alpha Evo Sport and Pro payloads are byte-identical; patching the
  `.sfu` cannot change the rating by itself.
