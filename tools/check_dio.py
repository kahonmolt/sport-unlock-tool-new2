import json

# Check all DeviceIoControl codes and if any have varying data
dio_codes = {}
with open(r'tools/usbcap/hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            if obj.get('api') == 'DeviceIoControl':
                code = obj.get('code', '')
                data = obj.get('data', '')
                if not code or not data:
                    continue
                dio_codes.setdefault(code, []).append(data[:16])  # first 8 bytes
                
        except: pass

print("=== All DeviceIoControl codes found ===")
for code in sorted(dio_codes.keys()):
    samples = dio_codes[code]
    unique_first8 = set(s[:8] for s in samples)
    print(f"Code={code}: {len(samples)} calls, {len(unique_first8)} distinct first-8-bytes patterns")

# Also check ReadFile data variance more carefully
print("\n=== ReadFile byte analysis ===")
byte_variants = {}
total_rf = 0
with open(r'tools/usbcap/hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            if obj.get('api') == 'ReadFile' and 'data' in obj:
                data = obj['data']
                total_rf += 1
                # Check each byte position for variance (skip first few constant bytes)
                for pos in range(0, min(len(data)//2, 64)):
                    hex_pos = pos * 2
                    if hex_pos + 2 > len(data): break
                    b = data[hex_pos:hex_pos+2]
                    byte_variants.setdefault(pos, set()).add(b)
        except: pass

print(f"Total ReadFile events: {total_rf}")
print("\nByte positions with variation (showing only non-constant bytes):")
for pos in sorted(byte_variants.keys()):
    variants = byte_variants[pos]
    if len(variants) > 1:
        print(f"  Byte {pos}: {len(variants)} distinct values — examples: {sorted(list(variants))[:5]}")
