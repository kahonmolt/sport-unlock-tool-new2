"""Read-only torque/calibration analysis of the decrypted ARM image."""
import struct, collections, math, sys

IMG = r'C:\projects\simagic-evo-sport-modification\tools\Alpha_Evo_Sport_decrypted.bin'
BASE = 0x240
d = open(IMG, 'rb').read()
img = d[BASE:]
print('image: %d bytes at file 0x%X, flash 0x08000000..0x080%X' % (len(img), BASE, len(img)))

# ---------------------------------------------------------------- 1. constants
print('\n== exact float constants ==')
cands = {
    '9.0': 9.0, '12.0': 12.0, '15.0': 15.0, '18.0': 18.0, '21.0': 21.0,
    '8.0': 8.0, '10.0': 10.0, '20.0': 20.0, '0.9': 0.9, '1.2': 1.2,
    '0.5': 0.5, '0.25': 0.25, '100.0': 100.0, '360.0': 360.0, '1000.0': 1000.0,
    '32768.0': 32768.0, '65535.0': 65535.0, '4096.0': 4096.0, '4095.0': 4095.0,
    '3.3': 3.3, '1.65': 1.65, '5.0': 5.0, '2.5': 2.5, '0.001': 0.001,
    '0.01': 0.01, '0.1': 0.1, '1.0': 1.0, '9.81': 9.81,
}
for name, v in cands.items():
    pat = struct.pack('<f', v)
    locs = [i + BASE for i in range(0, len(img) - 3, 4) if img[i:i + 4] == pat]
    if locs:
        print('  f32 %-8s @ %s' % (name, [hex(x) for x in locs[:8]]))

print('\n== exact double constants ==')
for name, v in (('9.0', 9.0), ('12.0', 12.0), ('15.0', 15.0), ('21.0', 21.0)):
    pat = struct.pack('<d', v)
    locs = [i + BASE for i in range(0, len(img) - 7, 4) if img[i:i + 8] == pat]
    if locs:
        print('  f64 %-6s @ %s' % (name, [hex(x) for x in locs[:8]]))

print('\n== small-value tables (runs of >=8 32-bit words all < 0x10000) ==')
runs, cur, start = [], 0, None
for i in range(0, len(img) - 4, 4):
    v = struct.unpack_from('<I', img, i)[0]
    if v < 0x10000:
        if start is None:
            start = i
        cur += 1
    else:
        if start is not None and cur >= 8:
            runs.append((start, cur))
        start, cur = None, 0
for s, n in runs[:25]:
    vals = struct.unpack_from('<%dI' % min(n, 16), img, s)
    print('  0x%06X  %d words  %s' % (s + BASE, n, ' '.join('%d' % v for v in vals)))

# ------------------------------------------------------- 2. region statistics
print('\n== 1 KB region map (off: zero%% ff%% entropy) ==')
for r in range(0, len(img), 0x400 * 8):
    seg = img[r:r + 0x400 * 8]
    z = seg.count(0) / len(seg)
    f = seg.count(0xFF) / len(seg)
    c = collections.Counter(seg)
    e = -sum((n / len(seg)) * math.log2(n / len(seg)) for n in c.values())
    print('  0x%06X  zero=%4.1f%%  ff=%4.1f%%  ent=%.2f' % (r + BASE, z * 100, f * 100, e))

# ------------------------------------------------- 3. most common 32-bit words
print('\n== most common 32-bit words in image ==')
wc = collections.Counter(struct.unpack_from('<%dI' % (len(img) // 4), img, 0))
for v, n in wc.most_common(25):
    print('  0x%08X  x%-6d  (%d)' % (v, n, v))

print('\n== most common words, excluding all-ones/zero ==')
shown = 0
for v, n in wc.most_common(200):
    if v in (0, 0xFFFFFFFF):
        continue
    print('  0x%08X  x%-6d  (%d)' % (v, n, v))
    shown += 1
    if shown >= 25:
        break
