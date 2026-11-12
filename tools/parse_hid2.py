import json
from collections import Counter, defaultdict

# Extract full SetFeature payloads per command type
sf_full = defaultdict(list)
rf_by_time = []

with open(r'C:\projects\simagic-evo-sport-modification\tools\usbcap\hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            api = obj.get('api', '')
            if api == 'HidD_SetFeature':
                data = obj.get('data', '')
                sf_full[data[:8]].append(data)
            elif api == 'ReadFile' and 'data' in obj:
                hex_data = obj['data']
                ts = obj.get('ts', 0)
                if len(hex_data) >= 82:
                    b39 = int(hex_data[78:80], 16)
                    b40 = int(hex_data[80:82], 16)
                    val = b39 + (b40 * 256) if b40 <= 127 else b39 + ((b40 - 256) * 256)
                rf_by_time.append((ts, api, obj.get('data', '')[:8], val))
        except Exception:
            pass

# Print full hex for first occurrence of each SF command type
print("=== Full SetFeature Payloads (first 128 hex chars = 64 bytes) ===")
for cmd in sorted(sf_full.keys()):
    samples = sf_full[cmd]
    print(f"\nCommand: {cmd} ({len(samples)} calls)")
    # Show first sample
    full = samples[0]
    print(f"  First: {full[:128]}")
    # Check if any vary beyond prefix
    unique_beyond = set()
    for s in samples:
        beyond = s[len(cmd):]
        unique_beyond.add(beyond)
    if len(unique_beyond) > 1:
        print(f"  VARIATION: {len(unique_beyond)} distinct payloads")
        # Show a few examples
        for ex in list(unique_beyond)[:3]:
            print(f"    ...{ex[:40]}")
    else:
        print(f"  ALL IDENTICAL beyond prefix (payload length: {len(samples[0])} hex chars)")

# Now correlate: for each non-801e command, what ReadFile follows?
print("\n=== 91040000 context (first 20 surrounding RF events) ===")
for ts, api, prefix, val in rf_by_time[:30]:
    marker = " <--" if prefix == '9104' else ""
    print(f"  {api:12s} pfx={prefix} byte39={val:+5d}{marker}")

print("\n=== 8005dddd context (first 20 surrounding RF events) ===")
for ts, api, prefix, val in rf_by_time[:30]:
    marker = " <--" if prefix == '8005' else ""
    print(f"  {api:12s} pfx={prefix} byte39={val:+5d}{marker}")
