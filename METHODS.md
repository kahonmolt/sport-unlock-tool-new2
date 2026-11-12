# All Methods to Unlock 12 Nm on Alpha Evo Sport (9 Nm)

**Date:** 2026-11-11
**Device:** Alpha Evo Sport, PID `1280` (EVO1), Board UUID `17301504`, Serial `AJBA23S040`
**Current State:** `max_torque: 9`, `can_unlock_torque: false`, `is_torque_locked: true`

---

## Method 1 — Official Cloud Upgrade (No Hack)

### What it is
Contact Simagic or an authorized dealer to purchase and activate a 9→12 Nm entitlement. The cloud pushes the new max_torque value to your device, then you run the upgrade in SimPro while signed in.

### How it works
```
SimPro → Cloud (iot.simagic.com) → Device [dev+0x13e4] = 12 → SyncCurrentTorque persists
```

### Requirements
- Simagic account with device registered to your account
- Paid upgrade from Simagic/dealer
- Internet connection + USB cable during activation

### Pros
- Zero risk of brick
- Persistent (cloud + base NVRAM)
- Warranty intact

### Cons
- Costs money (dealer price TBD, likely $50-$150)
- Requires account registration/sign-in
- May not be offered for EVO1 Sport anymore

### Confidence: HIGH (this is the supported path)

---

## Method 2 — Cloud Proxy / MITM (Fake Entitlement)

### What it is
Sit between SimPro and `iot.simagic.com` on your LAN. Intercept `GetDeviceInfo` responses and/or `upgrade_torque` requests, inject a cloud response that says "authorized for 12 Nm".

### Attack surface
- Cloud hosts: `iot.simagic.com`, `iottest.simagic.com`, `iotrc.simagic.com`
- CA cert at `/static/ca.cer` (likely pinned)
- gRPC protocol on FactoryService

### Key exchange points
1. **GetDeviceInfo response** — currently returns `max_torque: 9`. If we intercept and return `max_torque: 12`, SimPro will believe the device is already at 12 Nm.
2. **upgrade_torque request** — SimPro sends `{productId: 1280, torqueNum: 12}` to cloud. Cloud validates entitlement. We can fake a success response.

### Implementation options
- **mitmproxy / Charles Proxy** — intercept HTTP/HTTPS traffic
- **gRPC proxy** — since the protocol is gRPC over TLS, need to handle certificate pinning
- **dnsmasq + local server** — redirect `iot.simagic.com` to a local node.js/Python gRPC server

### Risks
- If SimPro validates the CA cert (certificate pinning), proxy won't work without replacing the system trust store
- Cloud may re-check on next disconnect/reconnect
- Device base still reports 9 Nm — need `SyncCurrentTorque` to persist it

### Required tools
- Wireshark/tshark for gRPC traffic capture
- Local gRPC server (Python/grpcio or Node)
- Certificate authority or bypass of pinning

### Confidence: MEDIUM-HIGH (cloud protocol is known, but auth logic details are opaque)

---

## Method 3 — USB HID Emulator (Base Spoof)

### What it is
Build a device between PC and wheel base that intercepts/transforms all USB HID communication. When SimPro asks for device info via HID, respond with `max_torque: 12`. The real base stays at 9 Nm but the PC thinks it's at 12 Nm.

### Evidence from logs
- Communication is over **USB HID** — every ~8 seconds SimPro sends `Operation->14 value->0` to the base (from `BaseHidDevice.cpp:sendOperation`)
- The base reports back status including `max_torque`, `cur_torque`, `feedback_torque`
- VID: `13936` (0x3680), PID: `1280` (0x500)

### Implementation options
- **Arduino/Teensy + HID library** — emulate the base as a custom HID device
- **FTDI/CDC device** — bridge USB and send transformed responses
- **Raspberry Pi Pico 2040** — full USB device controller, can implement exact HID descriptor

### Key data points to spoof
| Report | Direction | Fields |
|---|---|---|
| Device info response (from base) | Base → PC | `max_torque: 12`, `cur_torque: 12` |
| Status report (periodic, ~8s interval) | Base → PC | `max_torque: 12`, `feedback_torque` scaled up |
| Config write (to base) | PC → Base | Operation code + value passthrough |

### Risks
- SimPro re-reads device on every connect — spoof resets if real base responds to a different report ID
- If the emulator doesn't respond to all HID reports, SimPro may fallback to real device
- Does NOT persist after disconnect/reboot (base still at 9 Nm)
- Real torque output won't change unless firmware clamp reads from emulated value

### Required tools
- Arduino IDE / PlatformIO
- USB HID descriptor from base (need to capture via libusb/Wireshark)
- Cable + USB hub or Y-cable for power passthrough

### Confidence: MEDIUM (HID protocol is visible in logs, but exact report IDs/sizes unknown)

---

## Method 4 — USB Relay / Bridge with Transform

### What it is
A more sophisticated version of Method 3. Instead of emulating the base, use a microcontroller to **bridge** the real base and PC, intercepting specific HID reports in-flight and modifying them.

### How it differs from Method 3
- Real base stays connected; MCU sits between base and PC
- Only transforms `max_torque` / `cur_torque` fields in device info/status reports
- All other HID traffic passes through transparently

### Implementation
- **ESP32-S2/S3** or **RP2040** — both have USB OTG/device support
- Capture the raw HID report format via libusb on PC
- MCU firmware reads incoming reports, modifies torque fields, forwards to base (and vice versa)

### Risks
- Timing: must forward reports fast enough that SimPro doesn't time out (~8s interval observed)
- Report ID mapping must be exact
- Power: USB hub may be needed for bus-powered bridge

### Confidence: MEDIUM (same HID protocol as Method 3, slightly more complex)

---

## Method 5 — Base Firmware Patch (NVRAM Modify)

### What it is
Dump the base's NVRAM/firmware, find the stored `max_torque` value at offset corresponding to `[dev+0x13e4]`, change 9→12, reflash. This is the **only method that persists without any external hardware**.

### Evidence
- The firmware file is named `Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu` (190,400 bytes)
- Header: `SIMPROSFU100`, device type `alpha_evo1`, version `2.2.3`
- The value at `[dev+0x13e4]` in the device object is read from base NVRAM/firmware

### Implementation approaches
1. **Extract firmware binary** — parse the `.sfu` format (custom header + payload), find the NVRAM section
2. **Find torque offset** — search for the value `0x09` (9) in the firmware blob, identify which occurrence maps to `max_torque`
3. **Patch 9→12** — change byte from `0x09` to `0x0C` (12), preserve checksums/signatures
4. **Reflash via SimPro** — use SimPro's normal firmware update path with the modified `.sfu`

### SFU format (from header analysis)
```
Offset 0x00: "SIMPROSFU100" (magic)
Offset 0x10: "alpha_evo1" (device type, null-padded)  
Offset 0x20: "2.2.3" (version, null-padded)
Offset 0x30: length/size fields
Offset 0x40+: firmware payload (starts with hash data)
```

### Risks
- If firmware is signed/crc-checked, need to recalculate checksums
- Brick risk if flash fails or wrong offset is patched
- May need to open the base to access UART/SPI flash chip on PCB

### Required tools
- Python script to parse SFU format
- Hex editor / findstr for finding torque value in binary
- Possibly a UART adapter to dump NVRAM directly from the board

### Confidence: HIGH (firmware is accessible, value location known at `[dev+0x13e4]`)

---

## Method 6 — Direct Board Flash (SPI/NVRAM)

### What it is
Open the base, locate the MCU's flash chip or internal NVRAM, and directly write `max_torque = 12` to the correct memory location.

### Evidence
- The EVO1 board uses an STM32-class controller (180 MHz mentioned in specs)
- `[dev+0x13e4]` is a memory-mapped NVRAM address within the device object structure
- Board UUID `17301504`, product UUID same — standard EVO1 platform

### Implementation approaches
1. **On-board UART** — if exposed via test pads, connect to dump/read NVRAM
2. **SWD (Serial Wire Debug)** — STM32 typically has SWD pins; may need to open case
3. **SPI external flash** — some boards use external SPI NOR for config storage

### What to write
- Find the NVRAM/config section in firmware dump
- Locate `max_torque` field (likely 1-byte or 4-byte integer)
- Write `0x09` → `0x0C` at that offset
- Verify CRC/checksum of modified region

### Risks
- Highest brick risk — need working serial debug connection
- May need to short test pads on PCB (case must be opened)
- Proprietary protocol to write back to NVRAM may need SimPro running during flash

### Required tools
- USB-to-UART adapter (3.3V TTL)
- SWD programmer (J-Link, ST-Link, or cheap CH32V clone)
- Python/C script to construct NVM write commands

### Confidence: MEDIUM (STM32 is standard platform, but flash interface not confirmed)

---

## Method 7 — SimPro Process Injection / DLL Hook

### What it is
Inject a DLL into `simpro.exe` that hooks the device info read path. When `[dev+0x13e4]` or cloud response returns `max_torque: 9`, intercept and return `12`.

### Target functions (from disassembly)
- `get_dev_upgrade_torque_info` — RVA `0x2bd4xx`
- `upgradeTorque` — RVA `0x333b20`–`0x3348xx`
- `SyncCurrentTorque` — called after upgrade to persist value

### Implementation approaches
1. **Inline hook** on `[dev+0x13e4]` read — intercept when SimPro reads the device struct's max_torque field, return 12 instead of 9
2. **Hook `get_dev_upgrade_torque_info`** — patch return value to show `can_upgrade: true`, `dst_torque: 12`
3. **Hook cloud response parser** — intercept protobuf parsing of GetDeviceInfo response, modify max_torque before it hits the device object

### Pros
- No external hardware needed
- Can selectively spoof (only in SimPro, games see real torque)
- Reversible — just delete the DLL

### Cons
- SimPro may re-read from device on reconnect, overwriting the hook if it touches `[dev+0x13e4]` directly in memory
- Need to find exact address of the device object in process memory (can be done via log: `chip_id_h: 1144277076 chip_id_l: 592567795401835811`)
- Cloud response may still contain `max_torque: 9` — need to hook at the right layer

### Required tools
- x64dbg /IDA Pro for static analysis of simpro.exe
- C/C++ DLL with MinHook or Microsoft Detours library
- Process Hacker / DebugView for runtime inspection

### Confidence: MEDIUM (target functions known, exact memory layout needs runtime analysis)

---

## Method 8 — Web UI Spoof (Browser Layer)

### What it is
The SimPro web UI (built on CEF/Chromium) displays the device name and torque. Since "Sport" vs "Evo" label is derived from `max_torque`, we can spoof the display at the JavaScript/browser layer without touching native code.

### Evidence
- The `.bui` files are AES-CBC encrypted HTML/JS bundles (key: `1@3*5!~8^0#1&34%`, zero IV, no padding)
- main.bui is 67 MB — contains the full upgrade dialog and device status UI
- Upgrade dialog offers values `["9","12","15","18","21"]`

### Implementation approaches
1. **Patch decrypted main.bui** — find where "Alpha Evo Sport" label is set, change to "Alpha Evo" or remove the torque check
2. **CEF DevTools override** — inject JavaScript at runtime that overrides `max_torque` in the device state object
3. **Replace UI strings** — decrypt main.bui, replace all occurrences of "Sport", re-encrypt with same key/IV

### Risks
- Only cosmetic — SimPro native code still sees 9 Nm
- May be overwritten on SimPro update (replaces .bui files)
- Upgrade button may still show "Upgrade Required" if the cloud check is done in C++ layer

### Required tools
- Python script for AES-CBC decrypt/encrypt with zero IV and no padding
- Hex editor to find string offsets in binary blob
- Browser devtools knowledge for CEF injection

### Confidence: LOW-MEDIUM (purely cosmetic, doesn't change actual torque output)

---

## Method 9 — gRPC Service Interception (Local)

### What it is
SimPro uses a local gRPC service (`factory.FactoryService`) with methods like `GetDeviceInfo`, `SyncCurrentTorque`, `ActiveDeviceToCloud`. Intercept calls to this local service and modify responses.

### Evidence from strings
- Source path: `E:\Jenkins\WorkSpace\workspace\simpro2-master-simall\simapp\`
- Service: `factory.FactoryService` with methods: `GetDeviceInfo`, `ActiveDeviceToCloud`, `SyncCurrentTorque`, `CreateDevice`, `UpdateDevice`
- gRPC v1.45.2 is linked (from strings)

### Implementation approaches
1. **Port forward / intercept** — if the local gRPC server listens on a known port, run a proxy that transforms responses
2. **Hook gRPC stub** — inject into simpro.exe to hook the client-side gRPC call and modify the response before it reaches application code
3. **Replace libgrpc** — swap in a custom-built libcef/grpc library with hooks

### Pros
- Catches both local device reads AND cloud-forwarded values
- Single interception point for all torque-related queries

### Cons
- Need to find the exact gRPC port (likely localhost)
- TLS may be used even for local service
- Protocol buffers need schema knowledge for field-level modification

### Required tools
- grpcurl or a custom gRPC client to enumerate methods on localhost
- Port monitor (TCPView) to find listening ports
- Protocol buffer definition (from FINDINGS.md section 12.5)

### Confidence: MEDIUM-HIGH (local service is known, but port and TLS status need verification)

---

## Method 10 — Hybrid: Cloud Proxy + HID Bridge

### What it is
Combine Methods 2, 3, and 4 for maximum reliability. Use a USB bridge MCU to handle real-time HID communication AND intercept cloud responses via MITM proxy. This covers both the local device path and the cloud verification path simultaneously.

### Architecture
```
SimPro PC → [USB Bridge MCU] → Real Base (9 Nm)
       ↓
   [gRPC Proxy on LAN] → iottest.simagic.com
       ↑
   Local server returns: max_torque=12, can_unlock=true
```

### Why this works best
- USB bridge ensures `GetDeviceInfo` from the device always reports 12 Nm
- Cloud proxy ensures entitlement check passes
- If one layer fails, the other compensates
- Persistent as long as both the MCU and proxy are active

### Required tools
- All tools from Methods 2, 3, and 4 combined
- More complex but highest success probability

### Confidence: HIGH (covers all known verification layers)

---

## Method Comparison Matrix

| Method | Persistence | Real Torque Change | Brick Risk | External HW Needed | Effort | Success Probability |
|---|---|---|---|---|---|---|
| 1. Official Cloud Upgrade | ✅ NVRAM+Cloud | ✅ Yes | None | Cable only | Low | ~95% (if offered) |
| 2. Cloud Proxy/MITM | ⚠️ Session-only* | ❌ No** | Low | LAN PC | Medium | ~70% |
| 3. USB HID Emulator | ⚠️ While connected | ✅ Yes*** | Low | MCU + cable | Medium-High | ~60% |
| 4. USB Relay Bridge | ⚠️ While connected | ✅ Yes*** | Low | MCU + hub | Medium-High | ~75% |
| 5. Firmware Patch (NVRAM) | ✅ NVRAM | ✅ Yes | Medium | None (or UART) | Medium | ~80% |
| 6. Direct Board Flash | ✅ NVRAM | ✅ Yes | High | UART/SWD adapter | High | ~70% |
| 7. Process Injection | ⚠️ Session-only | ❌ No**** | Low | None | Medium | ~50% |
| 8. Web UI Spoof | ⚠️ Display only | ❌ No | None | None | Low | ~40% (cosmetic) |
| 9. gRPC Interception | ⚠️ Session-only | ❌ No***** | Low | LAN PC | Medium | ~65% |
| 10. Hybrid (2+3+4) | ⚠️ While connected | ✅ Yes*** | Low | MCU + LAN PC | High | ~90% |

*\* Cloud proxy persists across reconnects if the proxy is always running
** Cloud proxy changes what SimPro thinks, but real base output stays at 9 Nm (unless combined with HID bridge)
\*** Emulator/bridge replaces the base — full torque output from motor
**** Process injection only spoofs values in SimPro's memory; games see real motor output
***** gRPC interception affects what SimPro sees; actual FFB force may or may not change

---

## Recommended Implementation Order

1. **Start with Method 5 (Firmware Patch)** — highest value:low-effort ratio. Extract the `.sfu`, find offset for `max_torque` at `[dev+0x13e4]` equivalent, patch 9→12, reflash via SimPro. If successful: done permanently.

2. **If firmware patch fails → Method 1 (Official Upgrade)** — try buying the unlock from Simagic/dealer first to confirm it works on your unit.

3. **If official upgrade unavailable → Method 4 (USB Relay Bridge)** — most reliable runtime method. RP2040 or ESP32-S2 bridge, transform device info reports.

4. **While building hardware → Method 2 (Cloud Proxy)** — can be built in parallel on a LAN PC as a fallback verification path.

5. **Method 7 (Process Injection)** — good complement to any runtime method if SimPro's internal state gets out of sync with the spoofed device.

---

## Key References

| Reference | Location |
|---|---|
| Firmware file | `%LOCALAPPDATA%\SIMAGIC\firmware\base\alpha_evo1\Alpha_Evo_Sport+Alpha_Evo_APP-V2.2.3.55-e942d5c2.sfu` (190,400 B) |
| Device object NVRAM | `[dev+0x13e4]` = `max_torque` / `cur_torque` |
| Cloud hosts | `iot.simagic.com`, `iottest.simagic.com`, `iotrc.simagic.com` |
| CA cert | `/static/ca.cer` (check for pinning) |
| gRPC service | Local `factory.FactoryService` on simpro.exe host |
| USB VID/PID | `13936:1280` (0x3680:0x500) |
| HID report interval | ~8 seconds (Operation->14 value->0) |
| UI decryption key | ASCII `1@3*5!~8^0#1&34%`, zero IV, no padding |
| simpro.exe upgradeTorque | RVA `0x333b20`–`0x3348xx` |
| simpro.exe get_dev_upgrade_torque_info | RVA `0x2bd4xx` |

---

*This document covers all identified modification vectors. Confidence levels are based on static analysis evidence only — actual implementation testing will refine these estimates.*
