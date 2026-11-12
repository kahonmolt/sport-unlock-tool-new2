import os, re, json, glob, collections

LOGS = sorted(glob.glob(os.path.join(os.environ['LOCALAPPDATA'], 'SIMAGIC', 'log', 'simpro*.log')))
for LOG in LOGS:
    d = open(LOG, encoding='utf-8', errors='replace').read()
    print('=' * 70)
    print(os.path.basename(LOG), len(d), 'bytes')
    print('  base_status=%d  max_torque=%d  torque_limit=%d  adc=%d'
          % (d.count('base_status'), d.count('max_torque'), d.count('torque_limit'),
             d.lower().count('adc')))

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
    print('  distinct base_status blocks:', len(set(blocks)))
    for blk in list(set(blocks))[:3]:
        try:
            o = json.loads(blk)
            print('   ', json.dumps(o, sort_keys=True))
        except Exception:
            print('   ', blk[:300])

# device config: un-double-encode and print the base config portion
LOG = LOGS[-1]
lines = open(LOG, encoding='utf-8', errors='replace').read().splitlines()
for l in lines:
    if 'set selected device config' in l:
        m = re.search(r'->(\{.*)$', l)
        if not m:
            continue
        try:
            outer = json.loads(m.group(1))
            inner = json.loads(outer['config'])
        except Exception as e:
            print('parse fail', e)
            continue
        print('\nconfig preset:', inner.get('preset_name'), 'product', inner.get('product_id'))
        cfg = inner.get('config', {})
        for k in sorted(cfg):
            print('   %-28s %s' % (k, cfg[k]))
        print('   top-level keys:', sorted(inner.keys()))
        break

# any torque_limit values across the log
vals = collections.Counter(re.findall(r'\\"torque_limit\\":\s*"?([A-Za-z0-9_.-]+)', d))
print('\ntorque_limit values seen:', dict(vals))
