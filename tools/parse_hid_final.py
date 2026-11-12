#!/usr/bin/env python3
"""Final HID protocol analysis — complete byte parsing for all captured events."""
import json

sf_full = {}
rf_torques = []
sf_counts = {}

with open(r'C:\projects\simagic-evo-sport-modification\tools\usbcap\hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            api = obj.get('api', '')
            data = obj.get('data', '')

            if api == 'HidD_SetFeature':
                prefix = data[:8]
                sf_counts[prefix] = sf_counts.get(prefix, 0) + 1
                if prefix not in sf_full:
                    sf_full[prefix] = data

            elif api == 'ReadFile' and 'data' in obj:
                hex_data = obj['data']
                if len(hex_data) >= 82:
                    # Parse input report fields
                    byte0 = int(hex_data[0:2], 16)
                    byte1 = int(hex_data[2:4], 16)
                    byte2 = int(hex_data[4:6], 16)
                    status_word = (byte2 << 16) | (byte1 << 8) | byte0

                    byte3 = int(hex_data[6:8], 16)
                    byte12 = int(hex_data[24:26], 16)
                    byte28 = int(hex_data[56:58], 16)
                    
                    # Bytes 38-39 = signed int16 LE torque (check if we have enough data)
                    if len(hex_data) >= 82:
                        b38 = int(hex_data[76:78], 16)
                        b39 = int(hex_data[78:80], 16)
                        # Signed int16 LE
                        raw = b38 | (b39 << 8)
                        if raw > 32767:
                            torque = raw - 65536
                        else:
                            torque = raw
                    else:
                        torque = None

                    rf_torques.append({
                        'status_word': status_word,
                        'byte3': byte3,
                        'byte12': byte12,
                        'byte28': byte28,
                        'torque': torque,
                    })
        except Exception:
            pass

print(f"Total ReadFile events parsed: {len(rf_torques)}")
print()

# HID command counts
print("=== HID Output Command Counts ===")
for prefix in sorted(sf_counts.keys()):
    rid = int(prefix[0:2], 16)
    opcode = int(prefix[2:4], 16)
    print(f"  Report ID=0x{rid:02X} Opcode=0x{opcode:02X}: {sf_counts[prefix]} calls")

print()
print("=== Input Report Field Summary ===")

# Status word analysis
from collections import Counter
sw_counter = Counter(r['status_word'] for r in rf_torques)
b3_counter = Counter(r['byte3'] for r in rf_torques)
b12_counter = Counter(r['byte12'] for r in rf_torques)
b28_counter = Counter(r['byte28'] for r in rf_torques)

print(f"Status word (bytes 0-2): {len(sw_counter)} distinct values")
for sw, cnt in sorted(sw_counter.items()):
    print(f"  0x{sw:06X}: {cnt} readings")

print()
print(f"Byte 3 (counter/status): {len(b3_counter)} distinct values")
for val, cnt in sorted(b3_counter.items()):
    print(f"  0x{val:02X} ({val}): {cnt} readings")

print()
print(f"Byte 12 (sub-counter): {len(b12_counter)} distinct values")
for val, cnt in sorted(b12_counter.items()):
    print(f"  0x{val:02X} ({val}): {cnt} readings")

print()
print(f"Byte 28 (status): {len(b28_counter)} distinct values")
for val, cnt in sorted(b28_counter.items()):
    print(f"  0x{val:02X} ({val}): {cnt} readings")

# Torque analysis
valid_torques = [r['torque'] for r in rf_torques if r['torque'] is not None]
tc = Counter(valid_torques)
print(f"\n=== Torque Readings (bytes 38-39, signed int16 LE) ===")
print(f"Total readings: {len(valid_torques)}")
print(f"Zero/idle: {tc.get(0, 0)}")
print(f"Non-zero: {sum(v for k,v in tc.items() if k != 0)}")

# Show histogram of non-trivial torque values (|torque| >= 2)
non_trivial = [(k, v) for k, v in sorted(tc.items()) if abs(k) >= 2]
if non_trivial:
    print("\nNon-trivial torque readings:")
    for val, cnt in non_trivial[:15]:
        print(f"  {val:+4d} Nm: {cnt} readings")

# Show near-zero distribution
print("\nNear-zero distribution (|torque| < 2):")
for val in range(-3, 4):
    if val != 0:
        print(f"  {val:+d} Nm: {tc.get(val, 0)} readings")
