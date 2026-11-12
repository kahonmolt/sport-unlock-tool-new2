# Read-only torque analysis of the decrypted Alpha Evo firmware

Date: 2026-11-12 · Input: `tools/Alpha_Evo_Sport_decrypted.bin` (190,336 B, image at `0x240`,
flash `0x08000000..0x0802E580`) · Tools: `tools/img_torque.py`, `img_torque2.py`,
`img_utf16.py`, `img_table.py`, `img_dis.py`, `log_torque.py`, `log_config.py`.
Everything below is static reading only; no device I/O.

## 1. Torque / calibration constants — none found

Exact IEEE-754 searches over the whole image:

| Searched | Result |
|---|---|
| `9.0, 12.0, 15.0, 18.0, 21.0, 8.0, 10.0, 20.0` (f32 and f64) | **0 hits** |
| `0.9, 1.2, 9.81` (f32) | 0 hits |
| `3.3, 1.65` (f32, ADC reference candidates) | 0 hits |
| `0.001` (f32) | 0 hits |
| present: `100.0` (7×), `1000.0`, `4095.0` (2×), `4096.0` (2×), `65535.0`, `0.01`, `0.1` | generic scaling / ADC full-scale, not per-model |

Integer constants: there is **no** table of `9/12/15/18/21` in any width. The only `u32 9`
and `u32 10` literals in the image (0x27A10 and 0x27A70) sit inside hardware channel
descriptors together with peripheral pointers, e.g.:

```
027A00  a0 79 03 08 d8 79 03 08 00 00 00 00 29 cc 02 08
027A10  06 00 00 00 09 00 00 00 00 00 00 00 04 11 00 40      ; {count=6, chan=9}
...
027A70  05 00 00 00 0a 00 00 00 e8 79 03 08 00 00 00 00      ; {count=5, chan=10}
```

Those are DMA/ADC channel ids, not torque. No ADC calibration block, no current-threshold
table, no `torque`/`Nm` string (8-bit or UTF-16).

## 2. The one model-dependent structure in the image

At `0x282BC` there is a UTF-16LE name table — 8 records, stride `0x84`,
`{ u16 class; wchar_t name[65]; }`:

```
0282B0  eb 6c 50 a4 f7 a3 f9 be f2 78 71 c6 10 03 53 00
0282C0  49 00 4d 00 41 00 47 00 49 00 43 00 00 00 00 00   ; "SIMAGIC"
028340  24 03 53 00 49 00 4d 00 41 00 47 00 49 00 43 00   ; "SIMAGIC Alpha EVO"
```

| file off | class | name |
|---|---|---|
| `0x282BE` | `0x0310` (784) | SIMAGIC |
| `0x28342` | `0x0324` (804) | SIMAGIC Alpha EVO |
| `0x283C6` | `0x032C` (812) | SIMAGIC Alpha EVO Max |
| `0x2844A` | `0x032E` (814) | SIMAGIC Alpha EVO Plus |
| `0x284CE` | `0x032C` (812) | SIMAGIC Alpha EVO Pro |
| `0x28552` | `0x0330` (816) | SIMAGIC Alpha EVO Sport |
| `0x285D6` | `0x0330` (816) | SIMAGIC Alpha EVO Ultra |
| `0x2865A` | `0x0320` (800) | SIMAGIC Mark750 |

Notes:

- The firmware itself knows the names **Sport** and **Pro**, plus three names that are not
  in the shipped app (`Max`, `Plus`, `Ultra`) and `Mark750`.
- The class value is **not** a hash of the name (tested CRC16-CCITT/Modbus over ASCII and
  UTF-16, and a simple sum — none match), and it is **not** the torque: Max/Pro share
  `0x032C`, Sport/Ultra share `0x0330`.
- No 32-bit literal anywhere in the image points into `0x08028200..0x08028700`, so the table is
  not referenced by a literal-pool pointer; a `movw/movt`/`adr` path would still be possible and
  was not located. The names also do not exist in `simpro.exe` or in
  `%LOCALAPPDATA%\SIMAGIC\config`, so this table is firmware-private.
- Immediately after the table (`0x286D8`) is the **AES S-box** (`63 7c 77 7b f2 6b 6f c5 …`),
  i.e. the firmware carries its own AES implementation.

## 3. Sport vs Pro

Decrypted headers, side by side (the only bytes that differ, all in the 64-byte header):

```
0x00  53 49 4d 50 52 4f 53 46 55 31 30 30 00 00 40 00   SIMPROSFU100..@.   (both)
0x10  61 6c 70 68 61 5f 65 76 6f 31 00 ...               alpha_evo1  |  alpha_evo2   (0x19)
0x30  80 e7 02 00 | 00 00 08 01 | 00 00 08 01 | 00 05 70 36   Sport
      80 e7 02 00 | 00 00 09 01 | 00 00 09 01 | 01 05 70 36   Pro        (0x36,0x3A,0x3C)
```

| Region | Sport | Pro |
|---|---|---|
| `0x40..0x2E7BF` decrypted | identical | identical |
| image `0x240..EOF` (= flash image) | SHA-256 `b848b8af…30191` | **same hash** |
| header bytes differing | 4: `0x19`, `0x36`, `0x3A`, `0x3C` | |

Header fields are consumed **only by the PC app**:
`setUpdateFile` reads `file[0x40:]` into the payload buffer, so the 64-byte header
(including UUID/PID) **never reaches the wheel**. The handler at `simpro.exe` RVA `0x3E5340`
formats `hdr+0x34`/`hdr+0x38` as `%08X` and `hdr+0x3C`/`hdr+0x3E` as `%04X` and uses the
result solely as an SFU↔device compatibility key (`0x3E4940`, `0x3E3550`). No header field is
converted into a torque value anywhere.

The first 4 KB of the image itself (`0x240..0x1240`) is byte-identical between the two files;
the only divergence in the whole 190,400 bytes is the four header bytes above.

## 4. Image layout / word statistics

There is no separate data section. Per-1 KB entropy is 4.3–7.2 (median ≈5.9) across all 185 KB;
zero density 8–13 %; the image is Thumb-2 code with interleaved literal pools. The most common
32-bit words are opcodes, not data: `0x0000F2C2` ×988 (`movw`), `0xE7FF…` ×210 (`b .`),
`0x00004770` ×135 (`bx lr`), `0x080103CF` ×73 (default IRQ handler).

Data-like islands, and nothing else:

| Range | Content |
|---|---|
| `0x240..0x2FF` | Cortex-M vector table (73 × `0x080103CF`) |
| `0x279F0..0x27A90` | hardware channel descriptors (see §1) |
| `0x282BC..0x286DC` | model-name table (§2) |
| `0x286D8..0x28xxx` | AES S-box + tables |
| `0x2DFC0..0x2E580` | float DSP loop, ends with 8 × `0xFF` |

## 5. Log evidence (`simpro-2026-11-6.log`, `simpro-2026-11-9.log`)

`base_status` is the only torque-bearing record (2 distinct values, otherwise identical):

```json
{"bus_voltage":480,"can_fd_id":0,"can_id":0,"can_unlock_torque":false,
 "error":0,"error_code":0,"feedback_torque":0,"input":0,
 "is_torque_locked":true,"lock_torque_value":0,"max_torque":9,
 "mos_temp":39,"motor_temp":30,"output":0,"state":"run","state_code":2,
 "version":1,"wheel_id":6}
```

- `bus_voltage` 480 = **48.0 V** (scale ×10); temps in °C; torques are whole Nm.
- **No ADC counts, no current, no calibration fields.** The word `adc` appears 0 times in
  ~4.4 MB of log.
- `max_torque: 9` is the only rating value, reported by the wheel.
- `torque_limit` exists in the preset config (165×), always **`100`** — a user percentage
  of maximum, not the SKU rating.
- `GetDeviceInfo` returns `product_uuid 17301504`, `board_uuid 17301504`, `pid 1280`,
  `vid 13936`, `version_info 2.2.8`.

## 6. What actually differs at runtime

| Hypothesis | Verdict |
|---|---|
| (a) software limit read from NVM | **Supported.** One shared image serves 9–21 Nm SKUs; no rating constant exists in it; the value is reported as `max_torque` and persisted by the wheel. |
| (b) ADC current threshold in NVM | **No evidence.** No per-model current/ADC constants, tables or calibration blocks exist in the image, and no current/ADC values are reported over the protocol. |

So the difference is a **single software limit held in the wheel's NVM**, applied by
model-agnostic firmware — not a firmwired per-SKU current calibration. The firmware can,
however, name itself per model (§2), which means it does read a model/class value at
runtime; that value is data, not code.

## 7. Consequence for the 9→12 project

- Patching the `.sfu` cannot change the rating: there is no rating byte to patch, and both
  SKUs already run byte-identical code.
- The useful target is the NVM/command path. Note the firmware's own AES (S-box at
  `0x286D8`) and a 32-byte CTR block helper at `0x08021E10` (mirrors `simpro.exe:0xC98770`),
  which implies the host↔wheel config protocol is at least partly encrypted — that is the
  next read-only place to look.
