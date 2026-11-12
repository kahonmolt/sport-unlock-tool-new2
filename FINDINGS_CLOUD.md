# Cloud entitlement analysis — Simagic Alpha Evo

Date: 2026-11-12 · Scope: static reading of `simpro.exe` (21,927,424 B), the local
`%LOCALAPPDATA%\SIMAGIC` tree, the two `simpro-*.log` files and the bundled CA.
No network traffic was generated and nothing was modified.

> **Boundary.** This document explains how the entitlement mechanism is built and why the
> client cannot grant itself an unlock. It deliberately contains no forged responses, no
> certificate-bypass steps and no activation-code derivation.

---

## 1. Infrastructure as implemented

| Item | Evidence |
|---|---|
| Endpoints | `iot.simagic.com`, `iottest.simagic.com`, `iotrc.simagic.com` (strings `0xF5E408…0xF5E478`) |
| CA bootstrap | `https://iot.simagic.com/static/ca.cer` and `https://iottest.simagic.com/static/ca.cer`; cached to `\config\cloud\CA\ca.cer` |
| Local cloud config | `\config\cloud\cloud.json`, read by `getLocalCloudConfig` (`0xF5E4D0`); keys used: `address`, `auth`, `basic`, `token_address`, `produce`, `release`, `dev_no_privilege`, `dev_privilege` |
| Current content of `cloud.json` | `{}` (4 bytes) — all defaults |
| Auth | three hard-coded **HTTP Basic** credentials sit next to each host (`authorization` / `basic` / `Basic` at `0xF5E420`). Values are present in the binary but **redacted here**; they are vendor service credentials, not user tokens. |
| Transport | gRPC v1.45.2 (source paths `E:\grpc-v1.45.2\...`), protobuf 3.19.4, `grpc_ssl_credentials_create(pem_root_certs=…)` |

### The bundled CA is not a private CA

`static\ca.cer` (38,308 B) parses as:

```
subject : CN=E6, O=Let's Encrypt, C=US
issuer  : CN=ISRG Root X1, O=Internet Security Research Group, C=US
valid   : 2024-03-13 .. 2027-03-12     basicConstraints: CA=TRUE, pathlen=0
```

That is the public Let's Encrypt intermediate, not a Simagic root. No SPKI/public-key hash
appears anywhere in the binary, so there is **no visible certificate pinning** — validation
is ordinary chain validation against that bundle (or the OS store via schannel, which is also
linked). This matters for the assessment in §5, but it does not make the flow forgeable: a
response still has to come from a host presenting a certificate valid for `iot.simagic.com`.

## 2. gRPC surface (exact, from the embedded descriptors)

Service `factory.FactoryService`, eight registered methods (`0x1057950…0x1057A80`):

```
/factory.FactoryService/CreateDevice
/factory.FactoryService/UpdateDevice
/factory.FactoryService/GetDeviceInfo
/factory.FactoryService/ActiveDeviceToCloud
/factory.FactoryService/VerifyToken
/factory.FactoryService/UpdateTokenStatus
/factory.FactoryService/PrivilegeActivate
/factory.FactoryService/SyncCurrentTorque
```

Message schema (serialized `factory.proto` descriptor, `0x1048A42` onward):

| Message | Fields |
|---|---|
| `DeviceInfo` | product_uuid, device_uuid, factory_time, activate_time, board_uuid, chip_id_h, chip_id_l, version_info, encrypt_type, encrypt_key, activation_code, seed, serial_no, extern_serial_no, **max_torque** |
| `PrivilegeActivateRequest` | product_uuid, device_uuid, chip_id_h, chip_id_l, **current_torque, target_torque** |
| `PrivilegeActivatePsp` | status, result, message, name |
| `PrivilegeActivate` | encrypt_type, encrypt_key, **activation_code** |
| `TokenActivate` | encrypt_type, encrypt_key, **activation_code, target_torque** |
| `TokenActivatePsp` | status, result, message, name |
| `VerifyTokenRequest` | product_uuid, device_uuid, token, chip_id_h, chip_id_l |
| `VerifyActiveCodeRequest` | product_uuid, encrypt_type, encrypt_key, session |
| `ActiveDeviceToCloudRequest` | product_uuid, device_uuid, activate_time |
| `UpdateCurrentTorqueRequest` | product_uuid, device_uuid, **current_torque** |
| `UpdateTokenStatusToCloudRequest` | product_uuid, device_uuid, token, user |
| `DeviceQryReq` / `DeviceQryRsp` | chip_id_h/l → status, `DeviceInfo`, message, name |

Two things stand out:

1. The upgrade request carries **both** `current_torque` and `target_torque`, i.e. the server
   is asked to authorise a specific transition (9→12), not merely "unlock".
   (The descriptor defines both `PrivilegeActivate` — the code payload with
   `encrypt_type`/`encrypt_key`/`activation_code` — and `PrivilegeActivateRequest` — the
   identity + torque pair. Which one is the RPC input could not be resolved statically.)
2. The activation path is a **device-bound activation code**, and the response type (`Psp`)
   carries only `status/result/message/name`. The wheel-side state change is therefore not
   something the client invents from a boolean.

## 3. Where `can_unlock_torque` actually lives

`can_unlock_torque` has **exactly one** cross-reference in the whole 21.9 MB binary — a JSON
serializer at RVA `0xF64C4`:

```asm
000f64c4  lea  rdx, [rip + 0xe34d25]     ; "can_unlock_torque"
000f64cb  lea  rcx, [rbp - 0x20]
000f64cf  call 0x1400b1650               ; build std::string key
000f64d4  lea  rdx, [rbp - 0x20]
000f64d8  mov  rcx, rsi
000f64db  call 0x1400d3490               ; lookup value
000f64e1  movzx edx, byte ptr [rax]      ; <-- value read from the status struct
000f64e4  movzx ecx, byte ptr [rbx]
```

The neighbouring keys are identical in shape and each also has exactly one xref:
`max_torque` (`0xF5F9D`), `bus_voltage` (`0xF63B9`), `is_torque_locked` (`0xF65A2`),
`lock_torque_value` (`0xF6533`). Field offsets in the struct: `version` +0x30,
`can_unlock_torque` +0x44, `lock_torque_value` +0x48.

Consequences:

- The string is a **serializer key**, not a parser key. Nothing reads a config file, no
  protobuf field carries it, and no setter exists elsewhere in the binary.
- `can_unlock_torque` is **not** in the `factory.*` schema at all — the cloud never sends it.
  It is part of the base-status block that the app receives from the wheel and forwards to
  the UI (`SBrowserSignalHandle.cpp notifyConnectedDevicesMessage`), which is exactly where
  the log captures it.
- There is **no local entitlement cache**: `cloud.json` is `{}`, there is no token/user/
  licence file anywhere under `%LOCALAPPDATA%\SIMAGIC` (or `%APPDATA%`, which does not
  exist), and the preset metadata (`personal_preset\device_preset.json`) only lists game
  presets. The CEF profile (`cef_root_cache`, 32 MB, 115 files) was also checked: its
  `Local Storage\leveldb` and `Network\Cookies` contain only UI state (`ds8x_config`, page
  bookkeeping) — no `access_token`, `loginInfo`, `privilege` or torque keys.
- Both logs contain **zero** cloud entitlement traffic: no `PrivilegeActivate`,
  `VerifyToken`, `UpdateTokenStatus`, `upgrade_torque` or `Authorization` lines. This unit
  has never been signed in for an unlock.

So `can_unlock_torque: false` / `is_torque_locked: true` are **device-reported state**, and
the value the UI shows is a mirror of the wheel, not a client-side verdict that can be edited.

## 4. Observed flow

```
connect ──► wheel base_status (max_torque 9, is_torque_locked true, can_unlock_torque false)
        └─► cloud GetDeviceInfo(chip_id_h, chip_id_l) ──► identity + stored max_torque
UI "upgrade" ──► upgrade_torque ──► PrivilegeActivateRequest
                                     {product_uuid, device_uuid, chip_id_h, chip_id_l,
                                      current_torque: 9, target_torque: 12}
             ◄── PrivilegeActivatePsp {status, result, message, name}
on success ──► device applies authorized torque ──► SyncCurrentTorque
                                                    {product_uuid, device_uuid, current_torque}
```

`SyncCurrentTorque` was disassembled at `0x4AB5E0–0x4AB9A0`: it builds a
`UpdateCurrentTorqueRequest`, logs `send msg: {}`, issues the unary call
(`0x140C80A40`) and treats `[msg+0x28] == 0xC8` (HTTP 200) as success. It is **cloud
bookkeeping of the value the wheel already reported** — it does not write NVM and it is not
an unlock primitive.

## 5. Viability of each candidate approach

| Option | Finding |
|---|---|
| **A. Modify a local cache** | No cache exists. `can_unlock_torque` has one xref, a serializer; the only writable JSON is preset/UI config and `cloud.json` (endpoint/auth settings). Editing anything local changes what the app *displays*, not the wheel. |
| **B. Spoof the cloud response** | The decision is server-side and the request is device-bound (chip id pair + product/device UUID + torque transition). The response type carries only status/result/message — there is no field the client turns into a torque write by itself. Even with a valid TLS presentation, a forged `status: 200` does not move the wheel; the change is applied through the device protocol, which validates a vendor-issued activation code. |
| **C. Call `SyncCurrentTorque` alone** | It is a cloud write of `current_torque` (bookkeeping). The wheel's `max_torque` is unchanged, so the next status read overwrites it. Not an unlock. |
| **D. Factory/HID command that skips the check** | No such command exists in the app: there is no code path that sets `can_unlock_torque`, and the firmware is model-agnostic (previous finding) — the lock is NVM data applied by shared code, not a branch that can be latched open from the host. |
| **E. Certificate pinning** | No public-key/SPKI pinning found; a public Let's Encrypt intermediate is bundled and schannel is also linked. Hostname + chain validation still apply, and — more importantly — defeating TLS only gets you to option B's dead end. |

**Conclusion:** every client-side path either (i) changes only what SimPro displays, or
(ii) dies at the device, because the wheel holds the authoritative `max_torque` and accepts
a change only through the authorized, code-bound activation path. This matches the earlier
firmware result: the 9 vs 12 difference is a stored value that the vendor's server is the
authority for.

## 6. What would legitimately work

1. Ask Simagic / an authorised dealer to attach a 9→12 entitlement to the account+device
   (`PrivilegeActivate` would then return success and the normal upgrade applies it).
2. Check whether the Oct-2026 EVO program covers EVO1 at all — as documented earlier, the
   21 Nm campaign is for the **EVO Pro**, and the EVO1 store path may simply not offer an
   upgrade, in which case `can_unlock_torque: false` is the correct, permanent answer.
3. If the goal is more force rather than a specific SKU, a different base is the honest
   route; nothing in the software stack can add torque that the unit is not authorised for.

## 7. Reproducibility

| Artifact | Purpose |
|---|---|
| `tools/cloud_strings.py` | keyword sweep of `simpro.exe` for cloud/auth/torque strings |
| `tools/pexref.py` | RIP-relative xref finder used for the `can_unlock_torque` / RPC-name analysis |
| `tools/pedis.py` | annotated x64 disassembly of a PE RVA range |
| `tools/dis_sync.txt` | `SyncCurrentTorque` listing (`0x4AB5E0–0x4ABA20`) |
