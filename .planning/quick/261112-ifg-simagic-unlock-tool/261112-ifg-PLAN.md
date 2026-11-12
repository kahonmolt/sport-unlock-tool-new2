---
quick_id: 261112-ifg
slug: simagic-unlock-tool
date: 2026-11-12
status: planned
---

# Quick Task 261112-ifg: Simagic Torque Unlock Tool

## Description

Build the offline Simagic `.sfu` backup / patch / restore CLI described in
`tools/simagic_unlock_DESIGN.md`, using the crypto constants and format facts
established during the reverse-engineering session.

## Constraints and ground truth

- SFU: 64-byte header at `0x00`, AES-256-CTR ciphertext from `0x40` to EOF.
- Decrypted record: `u64 marker` at `0x40`, `u32 image_len` at `0x48`,
  `byte[20] digest` at `0x4C`, `0xFF` padding to `0x23F`, Cortex-M image at
  `0x240`.
- CTR is symmetric and position-based: re-encrypting the plaintext body with
  the same key/IV reproduces the original file byte-for-byte (verified: the
  re-encrypted fixture hashes to the original stock SFU SHA-256).
- The `0x4C` digest algorithm is unknown and was not reproduced by SHA-1,
  SHA-256, MD5, SHA-512, CMAC or HMAC variants. The tool must validate a
  digest before using it for re-signing and must never silently emit a file
  with an unvalidated digest.
- No unambiguous `max_torque` constant exists in the image (FINDINGS_READONLY
  section 1). The patch stage therefore searches candidates, scores them,
  and refuses to guess when the result is not unique.

## Tasks

### Task 1: Crypto + SFU container modules

- `tools/utils/crypto.py`: AES-256-CTR `crypt()`, key/IV constants, hash
  helpers, digest detection helper.
- `tools/utils/sfu.py`: header/record parsing, decrypt/encrypt assembly,
  image accessors, vector-table finder.

Verify: `python -m unittest discover -s tools/tests` crypto tests pass; the
round-trip of `tools/Alpha_Evo_Sport_decrypted.bin` equals the known stock SFU
SHA-256 `b20d4606...e52a47`.

### Task 2: Torque search + patch engine

- `tools/patch_nvm.py`: candidate scanning for int8/uint8/int16/uint16/int32/
  uint32/float32/float64 and scaled encodings; torque-ladder detection;
  context scoring; `apply_patch()`; `read_value()`.
- Refuses ambiguous auto-patch; supports explicit file offset.

Verify: unit tests over a synthetic ladder and over the real decrypted image.

### Task 3: Re-signing

- `tools/encrypt_sfu.py`: validate a stored digest against candidate
  algorithm/coverage pairs (SHA-1 then SHA-256 over the encrypted payload from
  `0x100`, then other safe coverages); re-sign only with a validated spec;
  `keep` mode preserves the original digest with a loud warning.

Verify: a synthetic SFU whose digest is SHA-1 of the encrypted payload
validates; the stock fixture reports no validated spec.

### Task 4: CLI + optional HID backup

- `tools/simagic_unlock.py`: `backup`, `patch`, `restore`, `info`, `scan`,
  `verify` subcommands with clear exit codes.
- `tools/utils/hid.py`: optional hidapi read-only backup (status report
  `0x23`, paged `0x90` config pages). Never writes torque.
- Patch writes a JSON sidecar so `restore` can reverse exactly, including the
  original digest to reproduce a byte-identical stock file.

Verify: CLI runs end-to-end on a temporary copy of the fixture; `restore`
reproduces the exact source bytes when the original digest was preserved.

### Task 5: Tests, docs, commit

- `tools/tests/test_simagic_unlock.py` covering crypto, container, search,
  signature detection and CLI flows.
- Note in `tools/README_simagic_unlock.md` (usage + limitations).
- Commit code and planning artifacts.

## Files

- `tools/simagic_unlock.py` (new)
- `tools/patch_nvm.py` (new)
- `tools/encrypt_sfu.py` (new)
- `tools/utils/__init__.py` (new)
- `tools/utils/crypto.py` (new)
- `tools/utils/sfu.py` (new)
- `tools/utils/hid.py` (new)
- `tools/tests/test_simagic_unlock.py` (new)
- `tools/README_simagic_unlock.md` (new)
- `.planning/STATE.md`, `.planning/quick/261112-ifg-simagic-unlock-tool/*`

## Out of scope

- Forging the cloud `PrivilegeActivate` token or writing NVM over HID.
- Solving the unknown `0x4C` digest construction.
