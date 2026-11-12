# Live USB / HID analysis — Alpha Evo Sport

Date: 2026-11-12 · Host: player1 · SimPro 2 running (7 processes) · Base connected
Status: **complete — real USBPcap `.pcap` plus API-level capture**
Supersedes the earlier versions of this file, which had no capture.

> **Scope.** Observation plus static disassembly. No torque value was changed on the
> device. The only write performed was a same-value write-back of feature report `0x23`
> (§8) to test writability.

---

## 1. USBPcap installation and capture

| Item | Result |
|---|---|
| Package | `USBPcapSetup-1.5.4.0.exe` (official desowin build, 195,040 B) |
| SHA-256 | `87A7EDF9BBBCF07B5F4373D9A192A6770D2FF3ADD7AA1E276E82E38582CCB622` |
| Authenticode | Valid — `CN=Tomasz Mon, O=Tomasz Mon, PL` (USBPcap author) |
| Installed to | `C:\Program Files\USBPcap\` (`USBPcapCMD.exe`, `USBPcap.sys`, `USBPcap.inf`) |
| CLI | **`USBPcapCMD.exe`** — there is no `usbpcap-cli.exe` and no `-l` option |
| Driver service | `USBPcap`, `sc create` + `sc start` → **RUNNING** |
| Class filter | `USBPcap` in `HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-…}\UpperFilters` |
| Control devices | `\\.\USBPcap1…5` exist after the reboot (8 probed, 5 real root hubs) |
| Capture | **60 s, 7,214,286 B** in `tools\usbcap\hub2.pcap` (112,440 packets) |

The 1.5.4.0 silent installer (`/S`) copies the files but **does not install the kernel
driver** on Windows 11 build 26100 (`USBPcap.sys` absent, no service). It was installed by
hand: copy the `.sys`, `sc create USBPcap type= kernel start= demand`, append `USBPcap` to
the USB class `UpperFilters`. PnP refuses to restart any device while a reboot is pending
("System reboot is needed to complete configuration operations!"), and no Config Manager
trick helped — see §1.1. A reboot was scheduled; after it the filter is in the stack:

```
USB\ROOT_HUB30\7&276CE0A&0&0        Stack: USBPcap, USBHUB3, ACPI, USBXHCI
USB\VID_3670&PID_0500\…             Stack: HidUsb, USBPcap, USBHUB3
```

**Second root cause found after the reboot:** the session came back at **Medium integrity**
because the new AtLogOn task runs with a limited token. At that level `USBPcapCMD` opens the
control device but captures nothing (0-byte files). Running the same command from the
**elevated** task produced the 7.2 MB pcap immediately.

Capture command actually used (elevated, all root hubs in parallel):

```powershell
USBPcapCMD.exe -d \\.\USBPcap2 -o hub2.pcap -s 512 -b 4096 -A --inject-descriptors
```

`-b 4096` matters: with the default 1 MB buffer a low-rate HID capture is lost when the
process is killed instead of stopped with Ctrl+C.

`QueryDosDevice` does **not** list `\\.\USBPcapN`; opening the name is the reliable test.

### 1.1 Attempts that did not avoid the reboot

| Attempt | Result |
|---|---|
| `sc start USBPcap` | driver RUNNING |
| `pnputil /restart-device` on the wheel, generic hub, root hub, xHCI controller | every call: "System reboot is needed…" |
| `CM_Reenumerate_DevNode` (flags 1 and 3) | rc=0, no control device |
| `CM_Disable_DevNode` on the root hub | rc=40, refused |
| Windows USB ETW (`USBPORT`, `USBHUB3`, `USBXHCI`, `UCX`, all keywords) | 171,872 events, **no payloads** (`DataSize=0`) |

---

## 2. Device identity and report descriptor

```
HID\VID_3670&PID_0500\D&15D8D0B3&0&0000
USB\VID_3670&PID_0500\2FF958DE5E001000
  BusReportedDeviceDesc : SIMAGIC Alpha EVO Sport
  Service               : HidUsb   Port_#0002.Hub_#0013   (behind 4 external hubs)
  VID/PID               : 0x3670 / 0x0500   (0x3670 = 13936, not 0x3680)
```

Full 345-byte HID report descriptor, recovered with `HidD_GetReportDescriptor`:

```
05010904a1010901a10085010930150027ffff0000751095018102093109320933093409350936
150026ff0f750c95068102c00600ff0901a10285800901150026ff003500460e017508953fb102
85810901150026ff007508953fb10285230901150026ff007508951fb10285830901150026ff00
75089510b10285030901150026ff007508953fb10285930901150026ff007508953fb102858409
01150026ff0075089510b10285950901150026ff007508953fb10285820901150026ff00750895
3fb10285900901150026ff00750895f0b10285910901150026ff007508953db10285fa09011500
26ff007508953fb102c08501050109391500250365147504950181020509190129741500250175
0195744500650081020600ff0901150025013500460e017508950e810285020904150025017508
953f8102850109021500250175089514910285020903150025017508953f9102c0
```

| Report ID | IN | OUT | FEATURE | Use seen on the wire |
|---|---|---|---|---|
| `0x01` | 41 B on the wire (64 B buffer) | — | — | joystick/FFB input, 108,046 transfers in 60 s |
| `0x02` | 63 | 63 | — | secondary input/output |
| `0x03` | — | — | 63 | wheel calibration |
| `0x07,0x09,0x20,0x21,0x22,0x23` | — | — | 16–63 | config blocks; **0x23 = status incl. torque** |
| `0x80–0x85` | — | — | 63 | command channel |
| `0x90` | — | — | **240** | paged base-config read (241 B total) |
| `0x91` | — | — | 61 | live status write |
| `0x93/0x95/0xfa` | — | — | 63 | factory/pick-type pages |

`HidD_SetFeature` is called with a 241-byte buffer for *every* feature ID; Windows transmits
only the report length declared for that ID (64 B for `0x80`, 62 B for `0x91`). This is why
the API capture shows 241-byte buffers while the wire shows 64/62.

---

## 3. Capture methods

### 3.1 Real USB capture (primary)

`tools/usbcap/hub2.pcap` — bus 2, device address 12, 112,440 packets, 60 s. Parser:
`tools/pcap_usb_extract.py` (DLT_USBPCAP 249, verified with `--selftest`), HID decoder:
`tools/pcap_hid_exchange.py`.

Important pcap semantics discovered: USBPcap sets info bit 0 for **device→host**
(completions carry IN data); host→device submissions are info 0 and carry `setup + payload`.
Reading the bit the other way makes every control-IN response look like a setup packet.

### 3.2 API capture (cross-check)

`tools/hid_hook.js` + `tools/hid_capture.py` hooked `HidD_*`/`ReadFile` on all seven
`simpro.exe` processes (45 s, 14,021 events, `tools/usbcap/hid_api_capture.jsonl`).

The two captures agree byte-for-byte on every frame below. SimPro's log correlation is also
exact: each `Operation->14` line lands within 0.1–1.4 ms of its HID write.

---

## 4. Captured frames — confirmed on the wire

### 4.1 Host → device (`SET_REPORT`, feature)

**A. `0x80` page select, op 14 — 6× in 60 s, period 7.56 s** (`value=0x0380`, 64 B)
```
80 05 dd dd 00 00 00 00 … (60 more zero bytes)
```
This is `sendOperation(14, 0)`. Op 12 = `80 05 bb bb`, op 13 = `80 05 cc cc`. The numbers
12/13/14 exist only in SimPro's log; on the wire the command is always `0x05` + a page byte.

**B. `0x80` FFB/effect stream — 1,675 SET_REPORTs in 60 s (~32 Hz, this includes A)**
```
80 1e 01 08 02 03 00 25 01 01 08 01 2a 21 10 01 18 01 42 05 15 f3 ea 62 00 42 08 08 80
02 15 e0 52 9c 00 42 08 08 80 04 15 85 4e ca 00 48 04 00 …
```
`80 1e 01 08` + protobuf effect body (`sendEffectData`, `effectRun SerializeToString`).

**C. `0x91` live status — 430× in 60 s (≈7.2 Hz)** (`value=0x0391`, 62 B)
```
91 04 00 00 00 a0 10 00 …
```

**D. `0x91` slow status — 19× in 60 s (0.32 Hz)**
```
91 05 00 00 00 00 00 00 …
```

No other host→device frame was sent. **No `80 1e … 53` upgrade frame appears** — the unit
has no entitlement, so SimPro never builds one.

### 4.2 Device → host (`GET_REPORT`, feature)

**E. `0x23`, 32 B — 8× in 60 s**
```
23 02 00 21 2b 09 00 00 00 00 06 00 00 e0 01 01 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```
`[0]` = report ID, **`[5]` = `0x09` = `max_torque`**. Parser at RVA `0x326c80` stores
`[1..0xf]` into `[dev+0x13d4 … +0x1404]`, byte 5 to `[dev+0x13e4]`.

**F. `0x90`, 241 B — 5× in 60 s** (paged config, read after the `0x80 05 dd dd` select)
```
90 1d 00 00 00 00 00 00 00 00 00 00 00 00 00 32 00 00 … 
```
With no preceding select the same report returns page 0 (`90 00 01 02 03 … 27 44 46 4b …`).

**G. Interrupt IN `0x01`, 41 B — 108,046 transfers in 60 s**
```
01 eb 7f 00 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 46 00 00 80
00 00 00 00 00 00 32 00 00
```
Axis/FFB state; `max_torque` is **not** here. (Windows pads 41→64 in the API layer.)

### 4.3 Protocol state machine (idle)

```
            every 7.56 s
  ┌──────────────────────────────────────────────────────────────┐
  │ GET_REPORT 0x23 (32 B)  ──► max_torque, state, temps         │
  │ SET_REPORT 80 05 dd dd  ──► device now serves page 0xdd      │
  │ GET_REPORT 0x90 (241 B) ──► that page's config block         │
  └──────────────────────────────────────────────────────────────┘
  every ~31 ms : SET_REPORT 80 1e 01 08 <effect protobuf>   (FFB)
  every ~7.2 Hz: SET_REPORT 91 04 <live status>
  every ~3.1 s : SET_REPORT 91 05 <slow status>
  continuously : IN report 0x01 (41 B)
```

---

## 5. Static map of the `0x80` command channel (simpro.exe)

| Packet | Builder RVA | Function | Purpose |
|---|---|---|---|
| `80 05 bb bb` | `0x3292f8` | status poll op 12 | select page `0xbb` |
| `80 05 cc cc` | `0x328630` | status poll op 13 | select page `0xcc` |
| `80 05 dd dd` | `0x328a8b` | status poll op 14 | select page `0xdd` |
| `80 10 39 00` | `0x330597` | `setBaseConfigPart1` | config chunk 1 |
| `80 09 44 44` | `0x330843` | `setBaseConfigPart2` | config chunk 2 |
| `80 05 24 23` | `0x33091c` | `setBaseConfigPart3` | config chunk 3 |
| `80 22/21/20/07 44 44` | `0x330b13…0x330d83` | config helpers | per-section writes |
| `80 0c 54 02` | `0x330e53` | config helper | section write |
| `80 10 38 00` | `0x331186` | `setConfigIncrement` | commit/increment |
| `80 1d 06 02`, `80 1e 01 08` | `0x32eada`, `0x32f51a` | `sendEffectData` | FFB stream |
| `80 1e … 53 …` | `0x3345e2` | **`upgradeTorque`** | **torque privilege frame (§6)** |

---

## 6. The only torque write path — and why it cannot be forged

Inside `upgradeTorque` (RVA `0x333b20`), after the EVO1 range check and the cloud call, the
function builds a 64-byte feature report at `0x3345e2 … 0x33465a`:

```asm
mov byte ptr [rax],   0x80          ; report ID
mov byte ptr [rax+1], 0x1e          ; extended-data command
movzx ecx, byte [rdi+0xf0] ; device field
mov byte ptr [rax+2], cl
movzx ecx, byte [rdi+0xf4] ; device field
mov byte ptr [rax+3], cl
mov byte ptr [rax+4], 0x53          ; 'S' = security / privilege block
mov byte ptr [rax+5], 3
mov byte ptr [rax+6], 0
mov byte ptr [rax+7], 0x20          ; 32-byte token
mov byte ptr [rax+8], 1
mov byte ptr [rax+9], 1
movups xmm0, [rbp+0x1c0] ; token[0..15]
movups [rax+0xa],  xmm0
movups xmm1, [rbp+0x1d0] ; token[16..31]
movups [rax+0x1a], xmm1
call 0x3b9a50                       ; queue SetFeature
```

Unlock frame:

```
80 1e <f0> <f4> 53 03 00 20 01 01 <32-byte encrypted token>
```

then it polls `[dev+0x13e4]` for the requested torque (timeout `0x77359400` ticks) and calls
`SyncCurrentTorque`.

Token construction, `0xc98650`:

```
plaintext[0..15]  = 16 bytes of the cloud/Psp context (device-bound)
plaintext[16]     = 0x07
plaintext[17]     = 0x01
plaintext[18]     = 0x01
plaintext[19]     = 0x01
plaintext[20..21] = 0x0001
plaintext[22]     = requested torque byte  ([rsp+0x40], 3rd argument of upgradeTorque)
   ↓ 0xc98110  AES key schedule (key material ctx+0x50 / ctx+0x30)
   ↓ 0xc97d20  AES encrypt (S-box at RVA 0x105c520)
ciphertext 32 bytes
```

The key material is the `encrypt_key` / `seed` pair from the cloud `PrivilegeActivate`
response. It does not exist on a unit whose `can_unlock_torque` is false — this unit.

---

## 7. Answers to the brief

**1. Can `max_torque = 12` be written with a single HID output report?**
No single report is accepted as a torque change. Report `0x23` is the only frame that
carries the value, and it is **read-only in practice**: eight `GET_REPORT 0x23` and zero
`SET_REPORT 0x23` in the capture, while every supported upgrade goes through the
`80 1e … 53` token frame. A raw `SET_REPORT` to `0x23` is accepted by Windows (same-value
write-back succeeded, §8) but there is no evidence the firmware honours a changed byte 5.

**2. What is the minimum sequence to force an unlock?**
The legitimate sequence is: `PrivilegeActivate` cloud round trip → **one** `SET_REPORT`
`80 1e <f0> <f4> 53 03 00 20 01 01 <32-byte token>` → device applies and updates NVRAM →
optional `SyncCurrentTorque`. There is no shorter local sequence; the token is the gate.

**3. Is there an HMAC/checksum in the HID protocol?**
Yes, on the one frame that matters: the 32-byte token is **AES-encrypted** (not a bare
checksum) and covers the device identity and the requested torque. The idle frames
(`0x23`, `0x80 05`, `0x90`, `0x91`) carry no checksum or MAC — they are plain structs, which
is why they can be replayed. The token cannot be generated without the cloud key.

---

## 8. Can the host write report 0x23?

Same-value test (`tools/hid_rw_probe.py`), no value changed:

| Step | Result |
|---|---|
| `GetFeature(0x23, 32)` | `230200212b0900…` → byte 5 = **9** |
| `SetFeature(0x23, same 32 bytes)` | **accepted**, returned 32 |
| `GetFeature(0x23, 32)` again | identical, byte 5 = 9, `changed=False` |

Report `0x23` is writable at the Windows/HID level and writing it does not disturb the
device. A **changed** byte 5 was deliberately not tested; it is a write to base
configuration and outside this capture's scope. The three reasons to expect it to be
ignored are: SimPro never writes it, the supported path uses the encrypted frame, and the
base is the party that commits the rating.

---

## 9. Conclusion

- **USBPcap works.** Driver installed by hand, filter in the USB stack, 60 s / 7.2 MB pcap
  from root hub `USBPcap2` (bus 2, device 12). The two blockers were the deferred-PnP
  reboot and, after it, a **non-elevated** session.
- **Wire format fully mapped** and identical to the API-level capture: `0x80` command
  (32 Hz FFB + 7.56 s page select), `0x91` status (7.2 Hz and 3.1 s), `0x23` status
  (torque at byte 5), `0x90` paged config, 41-byte `0x01` input report.
- **Torque is readable, not writable, from the host.** `max_torque = 9` appears in every
  `0x23` response. The only frame that changes it is the `80 1e … 53` AES token frame, which
  SimPro can only build from cloud `PrivilegeActivate` key material.
- **Direct HID unlock is therefore not possible on this unit.** A replay would require a
  token captured from an entitled unit *and* a key that validates on this device; neither
  is obtainable here.

---

## 10. Reproduction

```powershell
# elevated capture (all root hubs, 60 s), then decode
powershell -NoProfile -ExecutionPolicy Bypass -File tools\usbpcap_capture.ps1
python tools\pcap_usb_extract.py tools\usbcap\hub2.pcap
python tools\pcap_hid_exchange.py tools\usbcap\hub2.pcap
python tools\pcap_usb_extract.py --selftest        # parser check, no hardware

# API-level capture (no elevation needed for the HID API, but needs admin to inject)
python tools\hid_capture.py 60
python tools\hid_summarize.py
python tools\hid_timing.py
python tools\hid_correlate.py                     # joins %LOCALAPPDATA%\SIMAGIC\log
python tools\hid_probe.py                         # descriptor + feature dump
python tools\hid_rw_probe.py                      # same-value 0x23 write-back
```

Artifacts: `tools/usbcap/hub2.pcap`, `pcap_extract.txt`, `pcap_hid_exchange.txt`,
`hid_api_capture.jsonl`, `postreboot.log`.
