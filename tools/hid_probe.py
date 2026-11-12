"""Read-only probe of the Simagic wheel's HID report descriptor and feature reports."""
import sys

import hid

VID, PID = 0x3670, 0x0500

devs = hid.enumerate(VID, PID)
print(f"devices: {len(devs)}")
for d in devs:
    print({k: d[k] for k in ("path", "vendor_id", "product_id", "product_string",
                             "manufacturer_string", "serial_number", "interface_number",
                             "usage_page", "usage", "release_number")})

target = None
for d in devs:
    if d.get("usage_page") == 1 and d.get("usage") == 4:
        target = d
        break
if target is None and devs:
    target = devs[0]
if target is None:
    sys.exit("no device")

print("\nopening:", target["path"])
dev = hid.device()
dev.open_path(target["path"])
try:
    desc = bytes(dev.get_report_descriptor())
except Exception as exc:  # noqa: BLE001
    desc = b""
    print("get_report_descriptor failed:", exc)
print(f"report descriptor: {len(desc)} bytes")
print(desc.hex())

if desc:
    def parse(desc):
        out = {}
        rid, size, count = 0, 0, 0
        i = 0
        while i < len(desc):
            b = desc[i]
            i += 1
            if b == 0xFE:
                ln = desc[i]
                i += 3 + ln
                continue
            tag = b & 0xFC
            n = b & 0x03
            if n == 3:
                n = 4
            val = int.from_bytes(desc[i:i + n], "little") if n else 0
            i += n
            if tag == 0x84:
                rid = val
                out.setdefault(rid, {"in": 0, "out": 0, "feature": 0})
            elif tag == 0x74:
                size = val
            elif tag == 0x94:
                count = val
            elif tag in (0x80, 0x90, 0xB0):
                out.setdefault(rid, {"in": 0, "out": 0, "feature": 0})
                key = {0x80: "in", 0x90: "out", 0xB0: "feature"}[tag]
                out[rid][key] += size * count
        return out
    import json
    caps = parse(desc)
    print("\nparsed report sizes (bits):")
    print(json.dumps({hex(k): {kk: vv // 8 for kk, vv in v.items()} for k, v in caps.items()}, indent=2))

# Read-only feature queries observed from SimPro.
for rid, ln in ((0x90, 241), (0x23, 32), (0x80, 241)):
    try:
        data = bytes(dev.get_feature_report(rid, ln))
        print(f"\nfeature 0x{rid:02x} ({ln}B) -> {len(data)}B")
        print(data.hex())
    except Exception as exc:  # noqa: BLE001
        print(f"\nfeature 0x{rid:02x} ({ln}B) failed: {exc}")

dev.close()
