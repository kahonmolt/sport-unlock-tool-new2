---
quick_id: 261112-ifg
slug: simagic-unlock-tool
date: 2026-11-12
status: complete
---

# Summary: Simagic Torque Unlock Tool

## Delivered

| File | Purpose |
|---|---|
| `tools/simagic_unlock.py` | CLI: `backup`, `patch`, `restore`, `info`, `scan`, `verify` |
| `tools/encrypt_sfu.py` | digest validation + re-signing (SHA-1 then SHA-256) |
| `tools/patch_nvm.py` | torque candidate search/scoring, patch engine |
| `tools/utils/crypto.py` | AES-256-CTR, hardcoded key/IV, hash helpers |
| `tools/utils/sfu.py` | SFU header/record parser, decrypt/encrypt assembler |
| `tools/utils/hid.py` | optional read-only HID backup (report 0x23, pages 0x90) |
| `tools/tests/test_simagic_unlock.py` | 24 unit/CLI tests |
| `tools/README_simagic_unlock.md` | usage, safety model, exit codes |

## Verification

```
python -m unittest discover -s tools/tests -v
Ran 24 tests ... OK
```

Key verified behaviours:

- Re-encrypting `tools/Alpha_Evo_Sport_decrypted.bin` reproduces the stock SFU
  SHA-256 `b20d4606777720db7fb37cdf2c57efee17d84d97a67b11c92e90821098e52a47`.
- Header, record, padding and Cortex-M vector table parse correctly
  (`SP=0x20015BE0`, reset `0x080103B5`).
- Auto-patch exits 3 (no unique candidate) because the image is model-agnostic.
  The Thumb-2 TBB jump table at `0x1E68D` (`6/9/12/15`) is detected and
  rejected as a false positive.
- `patch --signature auto` exits 5 on the stock file because the `0x4C` digest
  is not reproducible. A synthetic package whose digest is SHA-1 of the
  encrypted payload validates and re-signs correctly.
- `patch --offset ... --signature keep` followed by `restore` reproduces the
  stock `.sfu` byte-for-byte (sidecar replays offset/encoding/original digest).
- Live HID backup read `max_torque=9` from the connected Alpha Evo Sport and
  dumped four 241-byte config pages; nothing was written to the device.

## Deviations / notes

- GSD quick requires a ROADMAP.md; none existed, so a minimal `.planning/`
  scaffold and a git repository were initialised first.
- The planner/executor subagents were not spawned: the work was fully
  specified by the design doc and reverse-engineering context, so the
  orchestrator implemented and verified it directly.
- Auto-patch intentionally refuses rather than guessing a byte. Patching the
  `.sfu` cannot change the rating on its own (`FINDINGS_READONLY.md`);
  `--offset` is the explicit escape hatch.
- The `0x4C` digest construction remains unsolved; `--signature keep` is
  available but documented as potentially rejected by the bootloader.
