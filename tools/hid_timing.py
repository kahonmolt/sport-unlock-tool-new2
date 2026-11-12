import json, datetime
from collections import Counter, defaultdict

p = 'tools/usbcap/hid_api_capture.jsonl'
rows = [json.loads(l) for l in open(p) if l.strip()]

print('handles by api:')
for k, v in Counter((r.get('api'), r.get('handle')) for r in rows).most_common():
    print(' ', k, v)

byp = defaultdict(list)
for r in rows:
    if r.get('api') == 'HidD_SetFeature' and r.get('phase') == 'enter':
        byp[(r.get('data') or '')[:8]].append(r['ts'])
for k, v in byp.items():
    v.sort()
    d = [round((b - a) * 1000, 1) for a, b in zip(v, v[1:])]
    print(f"\n{k} n={len(v)} first={datetime.datetime.fromtimestamp(v[0]).strftime('%H:%M:%S.%f')[:-3]} last={datetime.datetime.fromtimestamp(v[-1]).strftime('%H:%M:%S.%f')[:-3]}")
    print('  intervals ms: min', min(d) if d else None, 'median', sorted(d)[len(d) // 2] if d else None, 'max', max(d) if d else None)

print('\nGetFeature leave:')
for r in rows:
    if r.get('api') == 'HidD_GetFeature' and r.get('phase') == 'leave':
        print(' ', datetime.datetime.fromtimestamp(r['ts']).strftime('%H:%M:%S.%f')[:-3], r.get('len'), (r.get('data') or '')[:200])
