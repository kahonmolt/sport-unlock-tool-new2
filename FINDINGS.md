# Simagic Alpha Evo Sport/Pro firmware decryption — findings

Node: player1 (desktop-m8g7hv2\player1)
Date: 2026-11-12
Status: **payload decrypted.** AES-256-CTR, fleet-wide key+IV hard-coded in `simpro.exe`.
Artifacts: `tools/Alpha_Evo_Sport_decrypted.bin`, `tools/decrypted_first8k.txt`, `tools/fw_strings.txt`.

---

## 0. Bottom line

| Question | Answer |
|---|---|
| Is the `.sfu` payload encrypted? | Yes. |
| Cipher / mode | **AES-256-CTR** (16-byte big-endian counter, +1 per block). |
| Where is the key? | `simpro.exe` RVA `0x12C8730` (file `0x12C7330`), 32 bytes. |
| IV / counter0 | `simpro.exe` RVA `0x12C8750` (file `0x12C7350`), 16 bytes. |
| Encrypted range | file bytes `0x40 .. EOF` (190,336 bytes = 11,896 blocks). |
| Decrypted image base offset | `0x240` — valid Cortex-M vector table, SP `0x20015BE0`, reset `0x080103B5`. |
| Is the key per-device? | **No.** It is a fleet constant; it decrypts 14 of the 23 `.sfu` files in the local firmware cache, including P500, GTNeo, NeoX, FX, TB1 … |
| Is `max_torque` in the firmware? | **No.** See §6.4. |
| Is the payload patched-reflashable? | Not yet: the 20-byte digest at `0x4C` is of unknown construction (§6.5). |

The three things that made earlier attempts fail:

1. The key is **256-bit**, not 128-bit. The first 16 bytes of the key blob look like a normal AES-128 key, which is why 16-byte-only tests missed it.
2. The mode is **CTR**, not CBC/ECB. `Cipher.Decrypt(C0)` is *not* part of the construction, so an exhaustive "try every key as an ECB/CBC key" sweep can never find it.
3. Decryption starts at file offset **0x40**, not `0x100`, and the counter runs from `0x40`, so the block at `0x100` is block index 12 of the keystream.

---

## 1. Files examined

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `...\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu` | 190,400 | `b20d4606777720db7fb37cdf2c57efee17d84d97a67b11c92e90821098e52a47` |
| `...\alpha_evo2\Alpha_Evo_Pro_APP-V2.2.3.55-e942d5c2.sfu` | 190,400 | `8a96532ab7c9d241e694b8bafda2136af66ac870632b70c7605d004143ccc4e4` |
| `C:\Program Files (x86)\simpro2\bin\simpro.exe` | 21,927,424 | — |
| `C:\Program Files (x86)\simpro2\bin\simpro_1.dll` | 185,448 | — |

**The Sport and Pro payloads (`0x100..EOF`) are byte-for-byte identical** (verified over all
190,144 bytes). The header differs at exactly four byte positions, all header metadata:
`0x19` (device-name character), `0x36`, `0x3A`, and `0x3C`.

## 2. SFU structure (measured and code-confirmed)

```
0x000  "SIMPROSFU100"                 magic, 12 bytes + 00 00
0x00E  u16 = 0x0040                   header length (64)
0x010  char[16] "alpha_evo1"          device type, NUL padded
0x020  char[16] "2.2.3"               version, NUL padded
0x030  u32 = 0x0002E780 = 190,336     length of everything after 0x40 (= file_size - 0x40)
0x034  u32 = 0x01080000 (17301504)    product UUID
0x038  u32 = 0x01080000               board UUID
0x03C  u16 = 0x0500 (1280)            product id (PID)
0x03E  u16 = 0x3670 (13936)           vendor id (VID)
0x040  ...                            AES-256-CTR ciphertext to EOF
```

Pro header is identical except `alpha_evo2`, product/board UUID `0x01090000` (17367040),
PID `0x0501` (1281), VID unchanged.

Proof of the `0x3C`/`0x3E` split: `setUpdateFile`'s header handler
(`simpro.exe` RVA `0x3E5340`) formats `[hdr+0x34]` and `[hdr+0x38]` with `"%08X"`, and
`[hdr+0x3C]` and `[hdr+0x3E]` with `"%04X"`. The earlier reading of `0x3C` as a "header
checksum" was wrong — it is `PID || VID`.

## 3. The decryption

```
mode     AES-256-CTR
key      20 37 df 28 88 ab 45 f7 84 11 78 e2 5d 25 99 8c
         99 aa 34 77 43 83 ee 92 22 34 12 98 33 83 32 84
counter0 34 34 13 99 12 35 dd f3 39 38 99 a1 aa 84 32 99
```

For every 16-byte block `i` of `file[0x40+i*16 .. ]`:

```
ks[i] = AES256_Encrypt(key, counter0 + i)          # 128-bit big-endian, carry from byte 15
plain[i] = cipher[i] XOR ks[i]
```

CTR is symmetric, so re-encryption uses the identical operation. The keystream is
position-dependent only, which makes in-place patching of the plaintext trivial.

### 3.1 Where it is in the code

| Address (RVA) | What |
|---|---|
| `0x3E5500`–`0x3E6100` | `FwUpdateManager::setUpdateFile` — parses the SFU, decrypts the payload |
| `0x3E5F93` | `aes_ctr_init(ctx, key=0x12C8730, iv=0x12C8750)` |
| `0x3E5FE0`–`0x3E5FFF` | loop: `aes_ctr_crypt(ctx, buf+off, 0x20)` over 190,336 bytes |
| `0xC98110` | `aes_ctr_init(ctx, key, iv)` — clears ctx, key-expands, stores IV at `ctx+0xF0` |
| `0xC98140` | AES-256 key expansion (14 round keys; 13 in-loop rounds + final round) |
| `0xC97D20` | AES-CTR crypt: encrypts the counter, increments it, XORs into the buffer |
| `0xC98770` etc. | three other generic call sites of the same helper (32-byte block use) |

The 13-round loop in `0xC97D20` (`mov r13d, 0xd`) is the fingerprint of AES-256, not AES-128.

### 3.2 Device-type gate

`setUpdateFile` skips decryption for device types `0x0E` and `0x17..0x21`
(`alpha_hpm`, `up_mark1/2`, `mark300`, `deflrod`, `tb2-HD0`). `alpha_evo1`/`alpha_evo2`
resolve to type `0` and are always decrypted. The app therefore hands the base a
**plaintext** image over USB.

## 4. Decrypted file layout

```
0x040  ff ff ff ff ff ff ff ff      reserved / signature-absent marker (u64 -1)
0x048  u32 = 0x0002E580             image length = 189,824 = file_size - 0x240
0x04C  byte[20]                     digest, unknown construction (see §6.5)
0x060..0x23F                       0xFF padding
0x240..EOF                         Cortex-M flash image, 189,824 bytes
```

Entropy drops from **7.999 → 6.65** bits/byte, and the first 0x60..0x23F bytes are `0xFF`,
which is the proof the key/IV/mode are correct.

## 5. Decrypted image

### 5.1 Vector table at `0x240`

| Offset | Value | Meaning |
|---|---|---|
| `0x240` | `0x20015BE0` | initial SP (~87 KB of RAM) |
| `0x244` | `0x080103B5` | Reset |
| `0x248` | `0x0801B389` | NMI |
| `0x24C` | `0x08019881` | HardFault |
| `0x250` | `0x0801AFA9` | MemManage |
| `0x254` | `0x080112C1` | BusFault |
| `0x258` | `0x08021E91` | UsageFault |
| `0x26C` | `0x0801F7C5` | SVCall |
| `0x270` | `0x08016849` | DebugMon |
| `0x278` | `0x0801D34D` | PendSV |
| `0x27C` | `0x08020FB9` | SysTick |
| `0x280…` | `0x080103CF` | default IRQ handler |

Image spans `0x08000000`–`0x0802E580` (185 KB) on a Cortex-M4-class part with ≥128 KB SRAM.
That is consistent with the product spec (180 MHz controller, 20 kHz control loop).

### 5.2 Strings

There are 456 printable runs ≥ 4 bytes in the image, but 455 of them are Thumb-2 code
coincidences (`@BpG@`, `Q\`Qh`, …). The only real string is:

```
0x289B2  "array max size exceeded"
```

No `Simagic`, `STM32`, `SystemCoreClock`, `_start`, `main(`, `torque`, `Nm` strings exist.
This is a bare-metal DSP/control image, not an RTOS application with a string table.

### 5.3 First bytes (also in `tools/decrypted_first8k.txt`)

```
0040  ff ff ff ff ff ff ff ff 80 e5 02 00 77 dd b0 93  ................
0050  e9 29 41 e2 2a 91 77 7a db b3 01 28 46 e3 02 59  .)A.*.wz...(F..Y
0060  ff ff ... (0xFF to 0x23F)
0240  e0 5b 01 20 b5 03 01 08 89 b3 01 08 81 98 01 08  .[. ............
0250  a9 af 01 08 c1 12 01 08 91 1e 02 08 00 00 00 00  ................
0260  00 00 00 00 00 00 00 00 00 00 00 00 c5 f7 01 08  ................
0270  49 68 01 08 00 00 00 00 4d d3 01 08 b9 0f 02 08  Ih......M.......
```

## 6. Task results

### 6.1 Task 1 — the nine key hypotheses: all negative, as expected

Each was tested as AES-128 and AES-256, ECB and CBC/zero-IV, on the first block(s) at
`0x100`. Every one produced a non-ARM, high-entropy plaintext (`tag = -`). Full
hex output is preserved in `tools/fw_hypotheses.json`; representative results:

| # | Key derivation | First 32 bytes (ECB) | ARM? |
|---|---|---|---|
| A | SHA256("alpha_evo1"+"2.2.3") k128 | `69314ca60f6a43d57a5842c0e49da422…` | no |
| A | same, k256 | `ee94b66aa8475d2e9e727784f5f0a81c…` | no |
| C | HMAC-SHA256(uuid, payload) | `f607723bb86ca23e0533119407f436a9…` | no |
| D | HMAC-SHA256(board uuid bytes, payload) | `ff9f9b8dc6f34ba2d0646e737d7fb060…` | no |
| E | SHA256("alpha_evo1"+"00000000") | `f43af7f1513397b4c17a706c18455d14…` | no |
| F | MD5(SFU header 0x00..0x3F) | `d21a66bac5ab22b3b1cd3ebd27a24d66…` | no |
| G | SHA256(payload[0:32]) | `67062a46bb62dd4e4f261a3fbbd8c76a…` | no |
| H | nested HMAC("alpha_evo1","simagic") | `9b83ff7a4d87926ac36d96b7de71920f…` | no |
| I | SHA256(header 0x10..0x2F raw) | `c55f0082207b4b4ff5ecc9f0a5b131df…` | no |
| — | BUI key `1@3*5!~8^0#1&34%`, zero IV | `282f509a49d1406b12074e602af3ae87…` | no |

**Why they all failed:** none of these is the key, and none is used in ECB/CBC. The real
construction is CTR with a fixed 256-bit key, so even a *correct* 16-byte key would not
produce ARM bytes from `AES-Decrypt(C0)`.

Side note on the `byte[3] == 0xE7` marker: it is not a usable oracle. Over the 275,661
printable 16-byte strings in `simpro.exe`, 1,159 satisfy it by chance. All tests above
used a strict vector-table test (SP in `0x20000000..0x20100000`, 4-byte aligned; reset
vector odd in `0x08000000..0x08200000`) plus an entropy check on 4 KB of plaintext.

### 6.2 Task 2/3 — exhaustive key search in the binaries

Two independent sweeps were run.

**(a) PowerShell heuristic sweep** (earlier work): 275,661 printable 16-byte strings,
192,765 printable 32-byte strings, 243 hex-32 strings, 3,084 UTF-16LE keys, plus
XOR-masked and byte-reversed variants; 21.9M raw 16-byte windows and 21.9M raw 32-byte
windows. No real hit.

**(b) numpy vectorised full sweep** (`tools/aessweep.py`, added here): **every** byte
window of `simpro.exe`, unaligned, 16-byte keys and 32-byte keys, decrypting payload
blocks at `0x100/0x110/0x120` in ECB and CBC, testing all 16 plaintext alignments.

| Target | Candidate keys | Hits | Real hits |
|---|---|---|---|
| `simpro_1.dll` | 356,030 | 3 | 0 (all entropy 7.95) |
| `simpro.exe` | 43,852,524 | 168 | 0 (all entropy 7.95–7.97) |

Every hit is a statistical false positive: a wrong key yields ~8.0 bits/byte, while the
true plaintext is 6.65. The sweep is validated end-to-end by `tools/sweep_e2e_test.py`
(plants a known key, expects exactly one hit).

**Correct conclusion:** the key *is* stored verbatim in `simpro.exe` (RVA `0x12C8730`),
but a decrypt-the-ciphertext sweep cannot see it because the payload is CTR — the key
produces `E_K(counter)`, not `D_K(C)`. This is why (a) and (b) both come up empty and why
the earlier note "the key is assembled at runtime or fetched remotely" was wrong.

### 6.3 Task 4A–C — hex dump, vector table, strings

- 8 KB dump: `tools/decrypted_first8k.txt`
- Vector table: §5.1
- Strings: §5.2 (one real string, no vendor/MCU/boot banners)

### 6.4 Task 4D — `max_torque`: **not in the image**

Evidence:

- The **same** payload serves the 9 Nm Sport, the 12 Nm Evo, and the 15–21 Nm Pro.
  A 9 Nm unit and a 21 Nm unit run identical bytes, so the rating cannot be a constant
  in the firmware.
- No `torque`/`Nm` strings anywhere in the image.
- No `9/12/15/18/21` byte table, no `9.0f`/`12.0f`/`15.0f`/`18.0f`/`21.0f` floats, no
  corresponding doubles.
- The only per-unit value in the SFU header space is the product/board UUID and PID,
  which are *model* identifiers, not the rating.

Conclusion: `max_torque` / `cur_torque` is a per-unit NVM value (`[dev+0x13e4]` in the
app's device object, persisted by the base and mirrored in the cloud record), applied by
the firmware at runtime. **Patching the `.sfu` cannot change the torque rating**; the
value has to be changed where the base stores it.

### 6.5 Task 4E — the integrity record: partly solved

```
0x40  ff ff ff ff ff ff ff ff     u64 0xFFFFFFFFFFFFFFFF  (signature-absent / reserved)
0x48  u32 image length            189,824 (= file_size - 0x240) for EVO1
0x4C  byte[20]                    digest                       <-- algorithm unknown
0x60..0x23F                       padding, all 0xFF
```

Verified about the digest:

- It is **not** SHA-1, SHA-256 (either end), SHA-512 (head), MD5, or CRC32 of any
  contiguous range of the decrypted file, the encrypted file, or the trimmed image.
- It is **not** HMAC-SHA1/HMAC-SHA256 under the AES key, the BUI key, or `simagic`.
- It is **not** AES-CMAC of the image.
- Byte-reversed, 16-bit-swapped, 32-bit-swapped and `XOR 0xFF` variants of the image also
  do not reproduce it.
- The same record format appears in P500, GTNeo and NeoX (their lengths: 37,176 /
  78,128 / 81,240), all with the same `ff ff ff ff ff ff ff ff` prefix.

The app **never compares** this field: `setUpdateFile` decrypts in place and hands the
buffer to `updateBaseFirmware` with no digest check. So if anything verifies it, it is the
base's bootloader, not the PC app. Until the construction is known, a modified payload
cannot be given a valid digest — that, not the encryption, is the obstacle to patching.

## 7. Task 5 — Sport vs Pro verification

| Check | Result |
|---|---|
| Encrypted payloads identical | yes, all 190,144 bytes |
| Decrypted images identical | yes — image `0x240..EOF`, SHA-256 `b848b8afa10047e7d1c295dacb4e8d9a440f4f5df86db09361ea96f4b4530191` |
| Decrypted header block `0x40..0xFF` identical | yes |
| Header differences | 4 bytes: `0x19` (name), `0x36` (product UUID), `0x3A` (board UUID), `0x3C` (PID) |
| Per-device key derivation | none — a single fleet key decrypts both |

Cross-check: the same key decrypts **14 of 23** cached `.sfu` files to a canonical
Cortex-M vector table (EVO1, EVO2, P500, GTNeo, NeoX, FX, FXPro, GTC, GTS, P1000, P2000H,
TB1, TBRS, DS8X). The remaining 9 decrypt to structured (non-random) data but their
images do not start with a canonical vector table at a 4-byte offset — they are different
MCU families (N32/HPM) or use a different image offset. This is strong evidence the key
is a product-line constant, not a build constant.

## 8. What this enables and what it does not

Enables:

- Reading any `.sfu` payload offline (`tools/decrypt_sfu.py` recipe below).
- Reproducing the keystream and re-encrypting a modified image byte-exactly.
- Comparing firmware across products/versions.

Does not enable (yet):

- Changing `max_torque` — the value is not in the image.
- Re-signing a modified image — the `0x4C` digest construction is unknown, and the base
  bootloader's verification behaviour is untested.

## 9. Reproduction

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
KEY = bytes.fromhex('2037df2888ab45f7841178e25d25998c'
                    '99aa34774383ee922234129833833284')
IV  = bytes.fromhex('343413991235ddf3393899a1aa843299')

def crypt(buf40, key=KEY, iv=IV):
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    c, out = int.from_bytes(iv, 'big'), bytearray()
    for i in range(0, len(buf40), 16):
        ks = ecb.update((c + i // 16).to_bytes(16, 'big'))
        out += bytes(a ^ b for a, b in zip(buf40[i:i + 16], ks))
    return bytes(out)

sfu = open('Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu', 'rb').read()
plain = sfu[:0x40] + crypt(sfu[0x40:])     # idempotent: same function re-encrypts
```

Scripts in `tools/`:

| Script | Purpose |
|---|---|
| `decrypt_sfu.py` | the recipe above, plus header/record dump |
| `aessweep.py` | vectorised exhaustive AES key sweep (self-contained, self-tested) |
| `sweep_e2e_test.py` | end-to-end validation of the sweep with a planted key |
| `aes_selftest.py` | FIPS-197 + AES-256 round-trip check of the numpy AES core |
| `pefind.py` | RIP-relative xref finder for `simpro.exe` |
| `pedis.py` | annotated disassembler for a PE RVA range |
| `dis_setupdatefile.txt`, `dis_hdr64.txt`, `dis_su2.txt` | listings of the SFU code path |
| `fwprobe*.ps1`, `fwlib.cs`, `fw_hypotheses.json` | original PowerShell probe suite (negative results) |
| `Alpha_Evo_Sport_decrypted.bin` | full decrypted file (header + plaintext) |
| `decrypted_first8k.txt`, `fw_strings.txt` | dumps used in §5 |

## 10. Key addresses (simpro.exe)

| Item | RVA |
|---|---|
| `setUpdateFile` (SFU parse + CTR) | `0x3E5500`–`0x3E6100` |
| header handler, new format (len 64) | `0x3E5340` |
| header handler, old format (len 0) | `0x3E4E10` |
| AES-CTR init | `0xC98110` |
| AES-256 key expansion | `0xC98140` |
| AES-CTR crypt (13-round loop) | `0xC97D20` |
| firmware AES key (32 B) | `0x12C8730` |
| firmware CTR IV (16 B) | `0x12C8750` |
| `.bui` key (ASCII) | file `0xF35040` |
| `updateBaseFirmware` | `0x3E8820` (string refs `0x3E8870`+) |
