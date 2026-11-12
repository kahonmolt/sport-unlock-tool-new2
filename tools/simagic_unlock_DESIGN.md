# Simagic Torque Unlock Tool — Design Spec

## Overview
Standalone Python CLI tool to unlock Alpha Evo Sport (9 Nm → 12 Nm) without cloud dependency.
Supports Backup, Patch, and Restore operations on the SFU firmware file.

## Architecture

```
simagic_unlock.py          # Main CLI entry point
├── decrypt_sfu.py         # SFU decryption (AES-256-CTR)
├── patch_nvm.py           # Find & modify max_torque in decrypted firmware
├── encrypt_sfu.py         # Re-encrypt + re-sign modified firmware
└── utils/
    ├── crypto.py          # AES-256-CTR, hashing helpers
    └── hid.py             # HID device communication (backup/restore NVM)
```

## Known Constants

### SFU Format
```
Offset  Size   Field
0x00    64     Header (device name, UUIDs, PID, version string)
0x40    192    Hash/signature block (SHA-1/SHA-256 of payload + signature)
0x100   var    AES-256-CTR encrypted firmware payload
```

### Crypto Key (from simpro.exe RVA 0x12C8730)
```python
AES_KEY = bytes.fromhex("2037df2888ab45f7841178e25d25998c99aa34774383ee922234129833833284")
IV_COUNTER = bytes.fromhex("343413991235ddf3393899a1aa843299")
```

### Device NVM Layout (from earlier analysis)
```
Offset  Field              Type     Default (Sport)    Target (unlock)
0x13e4  max_torque         uint8/float   9                12
0x13e8  can_unlock_torque  bool        false            true
```

> NOTE: Earlier analysis confirmed NO IEEE754 float constants in ARM image.
> max_torque is likely stored as int8 or encoded value. The tool must search for both.

## Operations

### 1. BACKUP
```bash
python simagic_unlock.py backup --sfu <path_to_stock.sfu> --output <backup_dir>
```
- Decrypts SFU → saves raw firmware binary
- Saves original SFU header (UUIDs, PID)
- Optional: dump device NVM via HID ReadFile

### 2. PATCH
```bash
python simagic_unlock.py patch --sfu <path_to_stock.sfu> --output <patched.sfu> --torque 12
```
Steps:
1. Decrypt SFU payload (AES-256-CTR)
2. Search firmware binary for max_torque value(s):
   - Try int8 values: 9, 10, 11, 12
   - Try IEEE754 float32 LE patterns
   - Try encoded/scaled integer representations
3. For each candidate location, verify context (nearby known constants like 15.0, 18.0, 21.0)
4. Replace max_torque with target value
5. Re-encrypt modified payload
6. Compute new hash/signature block at offset 0x40
7. Copy original SFU header (preserving device UUIDs, PID)
8. Assemble final patched SFU

### 3. RESTORE
```bash
python simagic_unlock.py restore --sfu <path_to_patched.sfu> --output <restored_stock.sfu>
```
- Same as backup but reverses the patch (restore original torque value)

## Key Design Decisions

1. **No admin required** — uses Python hidapi or win32 API for HID operations
2. **Frida-independent** — crypto key and IV are hardcoded from earlier reverse engineering
3. **Deterministic re-signing** — hash/signature computed over encrypted payload at offset 0x40
4. **Safe patching** — verifies candidate locations by checking nearby known values before committing

## Unknowns to Resolve During Implementation
1. Exact size/type of max_torque field (int8? float32? encoded?)
2. Hash/signature construction at SFU offset 0x4C-0xFF
3. Whether device validates hash against encrypted payload or decrypted payload
