import json
from collections import Counter, defaultdict

# Parse HID report structure for each command type
sf_data = {}
rf_data = []
dio_data = []

with open(r'C:\projects\simagic-evo-sport-modification\tools\usbcap\hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            api = obj.get('api', '')
            data = obj.get('data', '')
            
            if api == 'HidD_SetFeature':
                prefix = data[:8]  # report_id + opcode + first 2 bytes
                sf_data.setdefault(prefix, []).append(data)
                
            elif api == 'ReadFile' and 'data' in obj:
                hex_data = obj['data']
                ts = obj.get('ts', 0)
                if len(hex_data) >= 82:
                    b39 = int(hex_data[78:80], 16)
                    b40 = int(hex_data[80:82], 16)
                    val = b39 + (b40 * 256) if b40 <= 127 else b39 + ((b40 - 256) * 256)
                rf_data.append((ts, hex_data[:82], val))
                
            elif api == 'DeviceIoControl':
                code = obj.get('code', '')
                if data:
                    dio_data.append((obj.get('ts',0), code, data[:128]))
        except Exception:
            pass

# Decode HID report structure for each SF command
print("=== HID Report Structure Decoding ===\n")
for cmd in sorted(sf_data.keys()):
    samples = sf_data[cmd]
    report_id = cmd[0:2]  # First byte
    opcode = cmd[2:4]     # Second byte  
    data_start = cmd[4:]  # Remaining prefix bytes
    
    print(f"Report ID: 0x{report_id} | Opcode: 0x{opcode} | Data: {data_start}")
    print(f"  Calls: {len(samples)}")
    
    # Decode first sample in detail
    full = samples[0]
    bytes_list = [full[i:i+2] for i in range(0, min(len(full), 48), 2)]
    dec = ' '.join(bytes_list)
    print(f"  Bytes: {dec}")
    
    # Check if any vary beyond first 16 hex chars (8 bytes)
    unique_beyond_8 = set()
    for s in samples:
        beyond = s[16:]  # Everything after first 8 hex chars (4 bytes)
        unique_beyond_8.add(beyond)
    
    if len(unique_beyond_8) > 1:
        print(f"  Varies after byte 4: {len(unique_beyond_8)} distinct")
        for ex in list(unique_beyond_8)[:2]:
            print(f"    ...{ex[:64]}")
    else:
        print(f"  ALL IDENTICAL (static command)")
    
    # Decode bytes as signed values where relevant
    if len(bytes_list) >= 10:
        b4 = int(bytes_list[4], 16)
        b5 = int(bytes_list[5], 16)
        b6 = int(bytes_list[6], 16)
        b7 = int(bytes_list[7], 16)
        print(f"  Byte4=0x{b4:02X} Byte5=0x{b5:02X} Byte6=0x{b6:02X} Byte7=0x{b7:02X}")
    print()

# Decode first few DeviceIoControl calls (HID descriptor reads)
print("=== First 3 DeviceIoControl calls ===")
for ts, code, data in dio_data[:3]:
    bytes_list = [data[i:i+2] for i in range(0, min(len(data), 64), 2)]
    dec = ' '.join(bytes_list)
    print(f"Code: {code}")
    print(f"Data: {dec}")
    # Check if this is a HID descriptor read (typically IO control code 0x80000003 or similar for HID)
    print()

# Show RF input report structure
print("=== Input Report Structure ===")
if rf_data:
    ts, hex_data, val = rf_data[0]
    bytes_list = [hex_data[i:i+2] for i in range(0, min(len(hex_data), 82), 2)]
    print("Byte positions and values:")
    for i, b in enumerate(bytes_list[:45]):
        byte_val = int(b, 16)
        # Show as signed int if > 127
        display = byte_val if byte_val <= 127 else byte_val - 256
        print(f"  [{i:2d}] 0x{b:>2s} (signed: {display:+4d})")
