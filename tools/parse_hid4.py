import json
from collections import defaultdict, Counter

# Build a precise timeline correlating HID ops with timestamps
events = []
with open(r'C:\projects\simagic-evo-sport-modification\tools\usbcap\hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            api = obj.get('api', '')
            ts = obj.get('ts', 0)
            
            if api == 'HidD_SetFeature':
                data = obj.get('data', '')[:8]
                events.append((ts, 'OUT_SF', data))
                
            elif api == 'ReadFile' and 'data' in obj:
                hex_data = obj['data']
                if len(hex_data) >= 40:
                    # Parse key fields from input report
                    byte12 = int(hex_data[24:26], 16)
                    byte28 = int(hex_data[56:58], 16)
                    
                events.append((ts, 'IN_RF', hex_data[:40]))
                
            elif api == 'DeviceIoControl':
                code = obj.get('code', '')
                if code in ('0xb0191', '0x220003', '0x22000b'):
                    events.append((ts, 'DIO', code))
        except Exception:
            pass

# Sort by timestamp (should already be sorted but ensure)
events.sort(key=lambda x: x[0])

# Show all non-telemetry OUT commands and what follows
print("=== All non-801e HID output events ===")
for i, (ts, etype, data) in enumerate(events):
    if etype == 'OUT_SF' and not data.startswith('801e'):
        # Show this event + next 3 events
        print(f"\n[{i}] OUT {data} at ts={ts:.4f}")
        for j in range(1, min(4, len(events) - i)):
            next_ts, next_type, next_data = events[i+j]
            if next_type == 'IN_RF':
                byte38_39_hex = next_data[76:82]
                print(f"  [{i+j}] IN  {next_data[:40]} ... b38-39={byte38_39_hex}")
            else:
                print(f"  [{i+j}] {next_type} {str(next_data)[:40]}")

# Count 9105 and 8005 occurrences with timestamps to see when they happen
print("\n=== 9105 events (36 total) ===")
count = 0
for i, (ts, etype, data) in enumerate(events):
    if etype == 'OUT_SF' and data.startswith('9105'):
        print(f"  [{i}] ts={ts:.4f}")
        count += 1
        if count >= 36: break

print("\n=== 8005 events (12 total) ===")
count = 0
for i, (ts, etype, data) in enumerate(events):
    if etype == 'OUT_SF' and data.startswith('8005'):
        print(f"  [{i}] ts={ts:.4f}")
        count += 1
        if count >= 12: break
