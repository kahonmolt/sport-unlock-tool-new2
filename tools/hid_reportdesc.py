"""Dump the HID report descriptor and parse report IDs / sizes."""
import winreg
import sys
import json

BASE = r"SYSTEM\CurrentControlSet\Enum\HID\VID_3670&PID_0500"
found = []


def walk(key, path):
    try:
        sub = winreg.OpenKey(key, r"Device Parameters")
        try:
            data, typ = winreg.QueryValueEx(sub, "ReportDescriptor")
            found.append((path, bytes(data)))
        except OSError:
            pass
        winreg.CloseKey(sub)
    except OSError:
        pass
    i = 0
    while True:
        try:
            name = winreg.EnumKey(key, i)
        except OSError:
            break
        i += 1
        try:
            child = winreg.OpenKey(key, name)
        except OSError:
            continue
        walk(child, path + "\\" + name)
        winreg.CloseKey(child)


with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, BASE) as k:
    walk(k, BASE)

print("descriptors found:", len(found))
for path, data in found:
    print(f"\n{path}  len={len(data)}")
    print(data.hex())

# Minimal HID report-descriptor parser: report IDs and report sizes.
def parse(desc):
    reports = {}
    rid = 0
    size = 0
    count = 0
    rtype = None
    i = 0
    stack = []
    while i < len(desc):
        b = desc[i]
        i += 1
        if b == 0xFE:  # long item
            ln, tag = desc[i], desc[i + 1]
            i += 3 + ln
            continue
        bTag = b & 0xFC
        bType = b & 0x0C
        bSize = b & 0x03
        if bSize == 3:
            bSize = 4
        data = desc[i:i + bSize]
        i += bSize
        val = int.from_bytes(data, "little") if data else 0
        if bTag == 0x84:  # Report ID
            rid = val
            reports.setdefault(rid, {"in": 0, "out": 0, "feature": 0})
        elif bTag == 0x74:  # Report Size
            size = val
        elif bTag == 0x94:  # Report Count
            count = val
        elif bTag == 0x80:  # Input
            reports.setdefault(rid, {"in": 0, "out": 0, "feature": 0})
            reports[rid]["in"] += size * count
        elif bTag == 0x90:  # Output
            reports.setdefault(rid, {"in": 0, "out": 0, "feature": 0})
            reports[rid]["out"] += size * count
        elif bTag == 0xB0:  # Feature
            reports.setdefault(rid, {"in": 0, "out": 0, "feature": 0})
            reports[rid]["feature"] += size * count
        elif bTag == 0xA0:  # Collection
            stack.append(rid)
        elif bTag == 0xC0:  # End Collection
            if stack:
                stack.pop()
    return reports


for path, data in found:
    print("\nparsed reports (bits):")
    print(json.dumps(parse(data), indent=2))
