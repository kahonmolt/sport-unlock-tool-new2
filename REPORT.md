# Simagic Alpha Evo Sport (9 Nm) vs Alpha Evo (12 Nm)

Technical analysis of SimPro Manager 2 and the connected Alpha Evo Sport.

Scope: static analysis of the installed SimPro Manager 2 binaries, configuration, logs, and decrypted UI bundles, plus targeted x64 disassembly of `simpro.exe`. No live USB bus capture and no modification of the wheel base were performed.

---

## 1. Bottom line

- **The 9 Nm "Sport" and 12 Nm "Evo" are the same hardware family.** Both enumerate as product ID `1280` (`EVO1`) with board UUID `17301504`, and both are served by the *same* firmware package (`Alpha_Evo_Sport+Alpha_Evo_APP`). The only per-unit difference that determines the displayed model name and torque ceiling is a stored `max_torque` / `cur_torque` value of **9 vs 12**, backed by a cloud entitlement.
- **There is no local "Sport/Evo" switch and no local unlock toggle.** The UI never writes a model flag. The upgrade path is an online transaction: the app fetches the device record from Simagic's cloud, obtains authorization, and the base applies the new torque.
- **The local code does permit a 9→12 request on an EVO1 unit** (range check is 9–12 Nm), but the request still fails without cloud authorization. The real gate is server-side entitlement, not the local check.
- **`can_unlock_torque: false` and `is_torque_locked: true` on this unit mean it currently has no unlock entitlement.** Simagic would have to grant/activate it.

So: shared hardware is strongly supported; the 9/12 distinction is a licensed calibration/entitlement, not a different motor or board. The widely repeated claim that the two differ "only by the power supply" is only partly right — the power supply may differ, but the functional restriction that SimPro enforces is a stored, cloud-authorized torque value.

---

## 2. Evidence that Sport and Evo share hardware

### 2.1 Device identity and firmware

From the live SimPro log (`%LOCALAPPDATA%\SIMAGIC\log\simpro-2026-11-9.log`):

```json
"base_status": {
  "can_unlock_torque": false,
  "is_torque_locked": true,
  "lock_torque_value": 0,
  "max_torque": 9,
  ...
},
"name": "Alpha Evo Sport",
"product_id": "1280",
"firmware_version": "228"
```

Device identity from the factory/cloud record:

| Field | Value |
|---|---|
| `product_id` | `1280` (`EVO1`) |
| `product_uuid` | `17301504` |
| `board_uuid` | `17301504` |
| `max_torque` | `9` |
| `serial_no` | `AJBA23S040` |
| `extern_serial_no` | `38YJ240428MA19F0088` |
| `device_uuid` | `3456891901066612736` |
| `chip_id_h` / `chip_id_l` | `1144277076` / `592567795401835811` |

Firmware shipped for the family:

| Path | Size | SHA-256 |
|---|---|---|
| `firmware\base\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu` | 190,400 B | `B20D4606…E52A47` |
| `firmware\base\alpha_evo2\Alpha_Evo_Pro_APP-V2.2.3.55-e942d5c2.sfu` | 190,400 B | `8A96532A…C4E4` |

The EVO1 package is explicitly named **"Alpha_Evo_Sport+Alpha_Evo"** — one image covers both the 9 Nm and 12 Nm variants. The EVO2 (Pro) image is the same size and version but a different build, consistent with a different board/mechanical platform.

### 2.2 Product mapping

`%LOCALAPPDATA%\SIMAGIC\config\product\device_product.json`:

| Name | productId | productUUID | productType |
|---|---|---|---|
| EVO1 | 1280 | 17301504 | 1 (base) |
| EVO2 | 1281 | 17367040 | 1 (base) |
| EVO3 | 1282 | 17498112 | 1 (base) |

`evo1_offical.product` and `evo2_offical.product` are byte-length-identical (1,837 B) and structurally identical except for `base:EVO1` vs `base:EVO2`. There is no separate "Sport" product definition — "Sport" is a label derived from the unit's torque value, not a distinct SKU in the product database.

### 2.3 Public spec corroboration

Sport and Evo share the same published dimensions (281 × 130 × 110 mm), weight (6.236 kg), 21-bit encoder, 180 MHz controller, and 20 kHz loop. The Pro is physically larger (317 mm, 8.627 kg). This matches the firmware/product-ID split: EVO1 = Sport/Evo, EVO2 = Pro.

---

## 3. What actually distinguishes "Sport" from "Evo"

Two independent pieces of state:

1. **Hardware family** — `product_uuid` / `board_uuid` (and the 16-bit `pid` read at `[dev+0xa]`). `17301504` = EVO1 board. This is fixed by the PCB and cannot be changed by software.
2. **Torque rating** — `max_torque` / `cur_torque`, stored per device in the cloud record keyed by `chip_id_h`, `chip_id_l`, and `device_uuid`, and mirrored in the base's NVRAM at `[dev+0x13e4]`.

SimPro derives the display name from these: EVO1 + `max_torque = 9` → **"Alpha Evo Sport"**; EVO1 + `max_torque = 12` → **"Alpha Evo"**. The value is read back from the device, not chosen by the user.

`get_dev_upgrade_torque_info` (RVA `0x2bd4xx`) returns:

```json
{ "serial_no": ..., "cur_torque": ..., "can_upgrade": ..., "dst_torque": ... }
```

with errors `get upgrade torque info error, device obj is null` and `device is not base`. This is the query the UI uses to decide whether to show an upgrade option.

---

## 4. The official unlock flow (from `upgradeTorque`)

Function at RVA `0x333b20`–`0x3348xx` in `C:\Program Files (x86)\simpro2\bin\simpro.exe`.

### 4.1 Request validation (local)

```asm
; requested torque must be strictly greater than current max_torque
movzx eax, dl
cmp   dword ptr [rcx+0x13e4], eax     ; [dev+0x13e4] = current max_torque
jl    continue
; else log "upgrade num error,torque_num = {}"

; EVO1 (pid 0x500 = 1280): allowed 9..12
movzx eax, word ptr [rcx+0xa]         ; 16-bit product id
mov   ecx, 0x500
cmp   ax, cx
jne   check_evo2
sub   dl, 9
cmp   dl, 3
jbe   allow                            ; 9,10,11,12

; EVO2 (pid 0x501 = 1281): allowed 15..21
mov   ecx, 0x501
cmp   ax, cx
jne   allow                            ; other pids skip the range check
sub   dl, 0xf
cmp   dl, 6
jbe   allow                            ; 15..21
```

Error strings: `upgrade num error,evo1 torque_num = {}` (`0xf51b30`), `upgrade num error,evo2 torque_num = {}` (`0xf51b58`).

Implications:
- A 9 Nm EVO1 may request 10, 11, or 12 Nm.
- A 12 Nm EVO1 cannot "upgrade" further within the family because the requested value must be strictly greater than current.
- The local check is a sanity/range check, not the security boundary.

### 4.2 Cloud + device exchange

1. Fetch the device record from Simagic's cloud by `chip_id_h` / `chip_id_l` (errors: `get device from cloud error`, `null`).
2. Obtain cloud authorization for the requested torque. The specific authorization exchange is outside the scope of this document.
3. The base applies the authorized torque value.
4. Poll `[dev+0x13e4]` until it equals the requested torque, with a timeout of `0x77359400` ticks (likely 2 s if the clock is nanosecond-based). On timeout: `upgrade torque error {}`.
5. On success, call `SyncCurrentTorque` to persist the new value (error: `SyncCurrentTorque error {} {} {}`).

### 4.3 UI side

The upgrade dialog in the decrypted `main.bui` bundle:

- Presents `["9","12","15","18","21"]` and pre-selects `sessionStorage.getItem("Nm") || "9"`.
- Calls `get_dev_info` (`bm({productId:e})` → `qg(Gg,e)`).
- Calls `upgrade_torque` (`qg($g,{productId:e,torqueNum:s.value})`).

So the UI offers all five values, but the server/device only accepts a transition the entitlement allows.

---

## 5. Is the restriction "just a power supply"?

Partly, but that is not what the software enforces.

- Hardware sharing is plausible and supported by the shared EVO1 firmware, identical board UUID, and identical dimensions/weight.
- However, the 9 vs 12 distinction SimPro acts on is a **stored torque calibration/entitlement** (`max_torque`, mirrored at `[dev+0x13e4]`), gated by cloud authorization.
- A different power supply may well be part of how Simagic builds the two retail SKUs, but swapping a PSU alone does not update `max_torque`, and the base will continue to report 9 Nm to SimPro.
- Conversely, even with a 12 Nm-capable supply, a 9 Nm unit without entitlement will not be authorized for 12 Nm.

The correct summary: **same EVO1 platform, different licensed torque calibration**, with the PSU possibly being one physical differentiator but not the software gate.

---

## 6. What this means for this specific unit

- `is_torque_locked: true`, `can_unlock_torque: false`, `lock_torque_value: 0` — no unlock is currently available/granted.
- The cloud `GetDeviceInfo` response returns `max_torque: 9`, and live status mirrors it. The device itself reports 9 Nm.
- There is no supported local action in SimPro that turns this into a 12 Nm Evo. The only supported path is contacting Simagic / an authorized dealer and having the entitlement activated on the account, then running the official upgrade in SimPro while signed in.

Note: Simagic's public 21 Nm upgrade campaign (SimPro 3.2.3, Oct 2026) applies to the **EVO Pro**, not the EVO1 Sport/Evo, and requires account registration/sign-in. Do not confuse that campaign with a 9→12 Sport→Evo upgrade.

---

## 7. Risks and caveats

- **Safety/warranty:** raising a 9 Nm-rated unit to 12 Nm may exceed the thermal/mechanical margin Simagic intended for the Sport SKU, even if the motor is shared. This can void warranty and stress the PSU and motor.
- **Licensing:** the upgrade is a paid/authorized entitlement. Circumventing it would violate Simagic's licensing, independent of the safety question. This analysis does not provide a crack.
- **Analysis limits:** conclusions come from strings plus targeted disassembly of `upgradeTorque`, `get_dev_upgrade_torque_info`, and `set_base_torque_lock_state`; no full decompilation or live bus trace was done. The Reddit "identical mechanically, different PSU" claim could not be verified (Reddit returned HTTP 403; the Facebook link was not retrievable).
- **Distinct feature:** `set_base_torque_lock_state` / `lock_state` / `auto_unlock_torque` is a separate torque-lock feature (parental/child lock style), not the SKU upgrade path.

---

## 8. Key locations

| Item | Location |
|---|---|
| SimPro binary | `C:\Program Files (x86)\simpro2\bin\simpro.exe` |
| `upgradeTorque` | RVA `0x333b20`–`0x3348xx` |
| `get_dev_upgrade_torque_info` | RVA `0x2bd4xx` |
| `set_base_torque_lock_state` | RVA `0x2d63c0`–`0x2d6900` |
| Device status log | `%LOCALAPPDATA%\SIMAGIC\log\simpro-2026-11-9.log` |
| Product map | `%LOCALAPPDATA%\SIMAGIC\config\product\device_product.json` |
| EVO1 template | `%LOCALAPPDATA%\SIMAGIC\config\product\offical_product\evo1_offical.product` |
| EVO1 firmware | `%LOCALAPPDATA%\SIMAGIC\firmware\base\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu` |
| gRPC service | `factory.FactoryService` (`GetDeviceInfo`, `SyncCurrentTorque`, …) |
| Cloud hosts | `iot.simagic.com`, `iottest.simagic.com`, `iotrc.simagic.com` |
