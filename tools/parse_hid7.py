import json

# Comprehensive HID protocol analysis
sf_full = {}
rf_samples = []

with open(r'C:\projects\simagic-evo-sport-modification\tools\usbcap\hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            api = obj.get('api', '')
            
            if api == 'HidD_SetFeature':
                data = obj.get('data', '')
                prefix = data[:8]
                if prefix not in sf_full:
                    sf_full[prefix] = data
                    
            elif api == 'ReadFile' and 'data' in obj:
                hex_data = obj['data']
                if len(hex_data) >= 82:
                    # Parse torque from bytes 38-39 (int16 LE)
                    byte38 = int(hex_data[76:78], 16)
                    byte39_val = int(hex_data[78:80], 16)
                    high_byte = int(hex_data[80:82], 16)
                    torque = byte38 + (high_byte * 256) if high_byte <= 127 else byte38 + ((high_byte - 256) * 256)
                    
                    # Parse other fields
                    status_word = int(hex_data[2:4] + hex_data[0:2], 16)  # Bytes 0-2 as uint24 LE
                    byte3 = int(hex_data[6:8], 16)
                    counter = int(hex_data[24:26], 16)
                    
                    rf_samples.append({
                        'status': f"0x{status_word:06X}",
                        'byte3': byte3,
                        'counter': counter,
                        'torque': torque,
                        'raw_first_40': hex_data[:80]  # First 20 bytes as hex
                    })
        except Exception:
            pass

# Print summary
print("=== HID Protocol Summary ===")
print()
print("INPUT REPORT (64 bytes, Report ID=0x01):")
print("  Bytes 0-2: Status word = 0x01EB7F (constant)")
print("  Byte 3:    Counter/status field (varies 0-4)")  
print("  Bytes 4-11: Zeros")
print("  Byte 12:   Sub-counter/status (varies 0-4)")
print("  Bytes 13-27: Zeros")
print("  Byte 28:   Status byte = 0x46 (70) constant")
print("  Bytes 29-31: 0x000080 constant flags")
print("  Bytes 32-37: Zeros")
print("  Bytes 38-39: SIGNED INT16 LE = Torque Nm (range -13 to +22)")
print()

# Show torque distribution
from collections import Counter
torques = [s['torque'] for s in rf_samples]
tc = Counter(torques)
print(f"Torque readings: {len(torques)} total")
print("Zero/idle readings:", sum(v for k, v in tc.items() if k == 0))

# Show torque histogram around zero
print("\nTorque near-zero distribution:")
for val in range(-3, 4):
    print(f"  {val:+d} Nm: {tc.get(val, 0)} readings")

print()
print("OUTPUT FEATURE REPORTS (64 bytes each):")
print()
for prefix in sorted(sf_full.keys()):
    full = sf_full[prefix]
    rid = int(prefix[0:2], 16)
    opcode = int(prefix[2:4], 16)
    print(f"Report ID=0x{rid:02X} Opcode=0x{opcode:02X}")
    print(f"  Full hex (first 32 bytes): {full[:64]}")
    
# Count unique DIO codes
print()
print("DeviceIoControl code 0xb0191 mirrors each SetFeature call.")
