import json
from collections import Counter

# Analyze DeviceIoControl calls in detail
dio_events = []
sf_events = []
rf_events = []

with open(r'C:\projects\simagic-evo-sport-modification\tools\usbcap\hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            api = obj.get('api', '')
            ts = obj.get('ts', 0)
            
            if api == 'DeviceIoControl':
                code = obj.get('code', '')
                data = obj.get('data', '')[:128]
                dio_events.append((ts, code, data))
                
            elif api == 'HidD_SetFeature':
                data = obj.get('data', '')[:8]
                sf_events.append((ts, data))
                
            elif api == 'ReadFile' and 'data' in obj:
                hex_data = obj['data']
                if len(hex_data) >= 40:
                    b39_hex = hex_data[78:82]
                    byte38 = int(hex_data[76:78], 16)
                    byte39 = int(b39_hex[:2], 16)
                    high_byte = int(b39_hex[2:4], 16)
                    val = byte38 + (high_byte * 256) if high_byte <= 127 else byte38 + ((high_byte - 256) * 256)
                rf_events.append((ts, val))
        except Exception:
            pass

# Print first 20 DIO calls in detail
print("=== First 20 DeviceIoControl Calls ===")
for i, (ts, code, data) in enumerate(dio_events[:20]):
    bytes_list = [data[j:j+2] for j in range(0, min(len(data), 64), 2)]
    dec = ' '.join(bytes_list)
    print(f"[{i:3d}] Code={code} Data: {dec}")

# Now correlate: what happens around each 9105 call?
print("\n=== Detailed context for first 5 x 9105 calls ===")
sf_idx = 0
for i, (ts, data) in enumerate(sf_events):
    if data.startswith('9105'):
        print(f"\n--- 9105 at sf[{i}] ts={ts:.4f} ---")
        # Show surrounding events
        for j in range(max(0, i-2), min(len(sf_events), i+6)):
            marker = " >>>" if j == i else ""
            print(f"  sf[{j:3d}] {sf_events[j][1]}{marker}")

# What about the first 8005 call?
print("\n=== First 3 x 8005 context ===")
for i, (ts, data) in enumerate(sf_events):
    if data.startswith('8005'):
        print(f"\n--- 8005 at sf[{i}] ts={ts:.4f} ---")
        for j in range(max(0, i-2), min(len(sf_events), i+6)):
            marker = " >>>" if j == i else ""
            print(f"  sf[{j:3d}] {sf_events[j][1]}{marker}")

# Check timing of 9105 calls - are they periodic?
print("\n=== 9105 call intervals ===")
prev_ts = None
for ts, data in sf_events:
    if data.startswith('9105'):
        if prev_ts is not None:
            interval = (ts - prev_ts) * 1000  # ms
            print(f"  Interval: {interval:.1f}ms between 9105 calls")
        prev_ts = ts
