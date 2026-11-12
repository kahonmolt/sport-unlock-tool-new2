import json

varying_status = set()
total_rf = 0

with open(r'tools/usbcap/hid_api_capture.jsonl') as f:
    for line in f:
        try:
            obj = json.loads(line)
            if obj.get('api') == 'ReadFile' and 'data' in obj:
                data = obj['data']
                total_rf += 1
                sw = data[:6]
                varying_status.add(sw)
        except: pass

print(f'ReadFile events: {total_rf}')
print(f'Unique status words (bytes 0-2): {len(varying_status)}')
for s in sorted(varying_status)[:5]:
    print(f'  hex={s.hex()}')

# Check if wheel is connected by looking for non-zero byte 3 (counter)
non_zero_b3 = sum(1 for _ in open(r'tools/usbcap/hid_api_capture.jsonl') 
                   if 'ReadFile' in _ and int(_.split('"data": "')[1][:6], 16) & 0xFF != 0)
