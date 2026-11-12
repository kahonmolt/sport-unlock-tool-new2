import json

# Check for ANY variation in SetFeature payloads per command type
sf_by_prefix = {}
total_sf = 0
varying_cmds = []

with open(r'C:\projects\simagic-evo-sport-modification\tools\usbcap\hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            if obj.get('api') == 'HidD_SetFeature':
                data = obj.get('data', '')
                total_sf += 1
                prefix = data[:8]
                sf_by_prefix.setdefault(prefix, []).append(data)
        except: pass

print(f"Total SetFeature calls: {total_sf}")
print(f"Unique prefixes (opcodes): {len(sf_by_prefix)}")
print()

for prefix in sorted(sf_by_prefix.keys()):
    samples = sf_by_prefix[prefix]
    rid = int(prefix[0:2], 16)
    opcode = int(prefix[2:4], 16)
    
    # Check for variation at every byte position beyond the 4-byte prefix
    unique_beyond_8 = set()
    for s in samples:
        unique_beyond_8.add(s[8:])
    
    if len(unique_beyond_8) > 1:
        varying_cmds.append((prefix, len(samples), len(unique_beyond_8)))
        print(f"VARYING: Report ID=0x{rid:02X} Opcode=0x{opcode:02X}")
        print(f"  {len(samples)} calls, {len(unique_beyond_8)} distinct payloads")
        
        # Show first few unique samples beyond prefix (first 32 hex chars = 16 bytes)
        seen = set()
        for s in samples:
            beyond = s[8:]
            key = beyond[:32]
            if key not in seen:
                print(f"    Sample: {s[:40]}...")
                seen.add(key)
                if len(seen) >= 3: break
    else:
        print(f"STATIC: Report ID=0x{rid:02X} Opcode=0x{opcode:02X}: {len(samples)} calls — all identical")

print()
if not varying_cmds:
    print("ALL commands are fully static across entire capture.")
else:
    print(f"Found {len(varying_cmds)} command type(s) with payload variation!")
