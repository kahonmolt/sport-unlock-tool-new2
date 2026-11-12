import json
from collections import Counter, OrderedDict

# Build timeline of HID operations
events = []
sf_counts = Counter()
rf_val_counts = Counter()

with open(r'C:\projects\simagic-evo-sport-modification\tools\usbcap\hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            api = obj.get('api', '')
            if api == 'HidD_SetFeature':
                data = obj.get('data', '')[:8]
                events.append(('SF', data, obj.get('ts', 0)))
                sf_counts[data] += 1
            elif api == 'ReadFile' and 'data' in obj:
                hex_data = obj['data']
                if len(hex_data) >= 82:
                    b39 = int(hex_data[78:80], 16)
                    b40 = int(hex_data[80:82], 16)
                    val = b39 + (b40 * 256) if b40 <= 127 else b39 + ((b40 - 256) * 256)
                else:
                    val = None
                events.append(('RF', val, obj.get('ts', 0)))
                rf_val_counts[val] += 1
        except Exception:
            pass

# Print unique SF commands
print("SetFeature commands:")
for cmd, cnt in sf_counts.most_common():
    print(f"  {cmd}: {cnt}")

# Print RF value distribution (top 30)
print("\nReadFile byte39 values (signed int16 LE):")
for val, cnt in sorted(rf_val_counts.items(), key=lambda x: -x[1])[:30]:
    print(f"  {val:+5d}: {cnt}")

# Print first 80 events as timeline
print("\n=== First 80 HID events (timeline) ===")
for i, (etype, val, ts) in enumerate(events[:80]):
    if etype == 'SF':
        print(f"  [{i:3d}] OUT {val}")
    else:
        print(f"  [{i:3d}] IN  {val:+5d}" if val is not None else f"  [{i:3d}] IN  None")
