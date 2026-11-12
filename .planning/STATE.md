# Project State

## Current Position

Milestone 1: Offline firmware tooling
Quick task 261112-ifg: Simagic Torque Unlock Tool

## Blockers/Concerns

- The `0x4C` 20-byte digest construction is still unknown. Re-signing is only
  applied when the stored digest can be reproduced from a known algorithm.
- `max_torque` is a per-unit NVM value; the SFU image contains no unambiguous
  rating constant (see FINDINGS_READONLY.md). Patch refuses unless a candidate
  is explicit or unique.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 261112-ifg | Simagic Torque Unlock Tool (backup / patch / restore CLI) | 2026-11-12 | 91bef50 | [261112-ifg-simagic-unlock-tool](./quick/261112-ifg-simagic-unlock-tool/) |

## Last activity

2026-11-12 - Completed quick task 261112-ifg: Simagic Torque Unlock Tool
