import re, os, pefile

P = r'C:\Program Files (x86)\simpro2\bin\simpro.exe'
d = open(P, 'rb').read()

def strings(data, minlen=4):
    pat = re.compile(rb'[\x20-\x7e]{%d,}' % minlen)
    for m in pat.finditer(data):
        yield m.start(), m.group().decode('latin1')

want = ['simagic.com', 'iottest', 'iotrc', 'ca.cer', 'static/', 'entitle', 'unlock',
        'activate', 'ActiveDevice', 'SyncCurrentTorque', 'FactoryService', 'factory.',
        'certificate', 'pinning', 'Authorization', 'Bearer', 'token', 'Token',
        'grpc', 'metadata', 'device_uuid', 'chip_id', 'product_uuid']

print('== keyword string hits ==')
seen = set()
for off, s in strings(d):
    low = s.lower()
    for w in want:
        if w.lower() in low:
            key = (w, s)
            if key in seen:
                break
            seen.add(key)
            print('  %-18s 0x%08X  %s' % (w, off, s[:120]))
            break

print('\n== proto / descriptor blobs ==')
for pat in (b'.proto', b'factory.', b'FactoryService', b'grpc.health', b'google.protobuf'):
    i = 0
    n = 0
    while n < 12:
        i = d.find(pat, i)
        if i < 0:
            break
        print('  0x%08X  %r' % (i, d[max(0, i - 40):i + 80]))
        i += 1
        n += 1
    print('  --', pat, 'total', d.count(pat))

print('\n== serialized FileDescriptorProto candidates (field names) ==')
for fld in [b'product_uuid', b'board_uuid', b'chip_id_h', b'max_torque', b'can_unlock_torque',
            b'cur_torque', b'lock_torque_value', b'dst_torque', b'serial_no']:
    hits = []
    i = 0
    while len(hits) < 8:
        i = d.find(fld, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    print('  %-20s %s' % (fld.decode(), [hex(x) for x in hits]))
