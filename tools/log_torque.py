import os, re, json, collections

LOG = os.path.join(os.environ['LOCALAPPDATA'], 'SIMAGIC', 'log', 'simpro-2026-11-9.log')
d = open(LOG, encoding='utf-8', errors='replace').read()
lines = d.splitlines()
print('log:', LOG, len(d), 'bytes,', len(lines), 'lines')
print('counts: base_status=%d max_torque=%d cur_torque=%d adc=%d current=%d calib=%d'
      % (d.count('base_status'), d.count('max_torque'), d.count('cur_torque'),
         d.lower().count('adc'), d.lower().count('current'), d.lower().count('calib')))

# 1) every base_status object, deduplicated
blocks = []
for m in re.finditer(r'"base_status"\s*:\s*\{', d):
    i = m.end() - 1
    depth = 0
    for j in range(i, len(d)):
        if d[j] == '{':
            depth += 1
        elif d[j] == '}':
            depth -= 1
            if depth == 0:
                blocks.append(d[i:j + 1])
                break
print('\n-- distinct base_status blocks: %d occurrences, %d distinct' % (len(blocks), len(set(blocks))))
for blk, n in collections.Counter(blocks).most_common(6):
    print('  x%-3d %s' % (n, blk.replace('\n', ' ')[:260]))

# 2) GetDeviceInfo cloud responses
print('\n-- GetDeviceInfo responses')
seen = set()
for m in re.finditer(r'GetDeviceInfo[^\n]*', d):
    s = m.group(0)
    if s not in seen:
        seen.add(s)
        print('  ' + s[:400])

# 3) device config JSON (may contain calibration)
print('\n-- set_device_config entries (unique keys only)')
keys = collections.Counter()
sample = {}
for l in lines:
    if 'set selected device config' in l:
        for k in re.findall(r'\\"([a-z_0-9]+)\\"', l):
            keys[k] += 1
            sample.setdefault(k, l[:300])
for k, n in keys.most_common(60):
    print('  %-28s x%-4d' % (k, n))
print('\n-- first set_device_config line')
for l in lines:
    if 'set selected device config' in l:
        print(l[:1200])
        break

# 4) any numeric fields that look like calibration
print('\n-- lines mentioning adc/current/calib/force (unique shapes)')
shapes = collections.Counter()
for l in lines:
    ll = l.lower()
    if any(k in ll for k in ('adc', 'calib', 'current', 'feedback')):
        shapes[re.sub(r'\d+', 'N', l)[:200]] += 1
for s, n in shapes.most_common(20):
    print('  x%-4d %s' % (n, s))
