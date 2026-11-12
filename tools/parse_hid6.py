import json

# Extract first complete payload for each SF command type and DIO calls
sf_full = {}
dio_by_type = {}

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
                    
            elif api == 'DeviceIoControl':
                code = obj.get('code', '')
                data = obj.get('data', '')
                if data and len(data) >= 32:
                    # Group by first 8 hex chars of DIO data
                    dio_key = data[:8]
                    if dio_key not in dio_by_type:
                        dio_by_type[dio_key] = []
                    dio_by_type[dio_key].append((obj.get('ts',0), code, data))
        except Exception:
            pass

print("=== Complete SetFeature Payloads ===")
for prefix, full in sorted(sf_full.items()):
    print(f"\nPrefix: {prefix}")
    print(f"Full ({len(full)//2} bytes): {full[:192]}...")  # First 96 bytes
    
    # Decode byte by byte for first 30 chars
    dec_parts = []
    for i in range(0, min(len(full), 60), 2):
        b = int(full[i:i+2], 16)
        dec_parts.append(f"b{i//2}=0x{b:02X}")
    print("Structure:", ' | '.join(dec_parts[:30]))

print("\n=== DeviceIoControl by data prefix ===")
for dio_key, calls in sorted(dio_by_type.items()):
    code = calls[0][1] if calls else "?"
    print(f"\nDIO key={dio_key} Code={code} ({len(calls)} calls)")
    # Show first call details
    ts, _, data = calls[0]
    bytes_list = [data[j:j+2] for j in range(0, min(len(data), 64), 2)]
    print(f"  First: {' '.join(bytes_list[:32])}")
